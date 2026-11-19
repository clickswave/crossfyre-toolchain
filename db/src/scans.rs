//! The tables every engine has (`scans`, `logs` and `operations`), written the same way
//! by each, on a pool [`crate::ensure_ready`] gave it, which looks in the engine's own
//! schema.

use sqlx::PgPool;

/// Where a scan or an operation is: the same names in every engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Made, and not started.
    Queued,
    Running,
    /// Ended before it was done: the caller went away, it was halted, or the daemon
    /// running it exited. A scan with the same settings takes it up again.
    Stopped,
    Completed,
    Failed,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Queued => "queued",
            Status::Running => "running",
            Status::Stopped => "stopped",
            Status::Completed => "completed",
            Status::Failed => "failed",
        }
    }
}

/// The scan a request runs as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Started {
    pub id: String,
    /// Whether it is a stopped scan taken up again, rather than a new one.
    pub resumed: bool,
}

/// Keys whose values are credentials, at any depth of a request's parameters, as
/// [`secret_key`] spells them.
const SECRET_KEYS: &[&str] = &[
    "auth",
    "authorization",
    "proxyauthorization",
    "cookie",
    "cookies",
    "setcookie",
    "token",
    "accesstoken",
    "refreshtoken",
    "idtoken",
    "bearer",
    "password",
    "passwd",
    "secret",
    "clientsecret",
    "apikey",
    "xapikey",
    "credential",
    "credentials",
    "session",
    "sessionid",
];

/// Whether `key` names a credential, compared in lower case with `-` and `_` taken out,
/// so that `X-Api-Key`, `api_key` and `apiKey` are one name.
fn secret_key(key: &str) -> bool {
    let key: String = key
        .chars()
        .filter(|c| *c != '-' && *c != '_')
        .flat_map(char::to_lowercase)
        .collect();
    SECRET_KEYS.contains(&key.as_str())
}

/// Whether `line` is a header (`Name: value`) that carries a credential.
fn secret_header(line: &str) -> bool {
    line.split_once(':')
        .is_some_and(|(name, _)| secret_key(name.trim()))
}

/// `url` without the user and password it names, when it names them.
fn without_userinfo(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let (_, host) = authority.rsplit_once('@')?;
    Some(format!("{scheme}://{host}{tail}"))
}

/// Take every credential out of `value`, and say whether there was one.
fn strip(value: &mut serde_json::Value) -> bool {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            let had = map.len();
            map.retain(|key, _| !secret_key(key));
            let mut removed = map.len() != had;
            for v in map.values_mut() {
                removed |= strip(v);
            }
            removed
        }
        Value::Array(items) => {
            let had = items.len();
            items.retain(|v| !v.as_str().is_some_and(secret_header));
            let mut removed = items.len() != had;
            for v in items.iter_mut() {
                removed |= strip(v);
            }
            removed
        }
        Value::String(text) => match without_userinfo(text) {
            Some(clean) => {
                *text = clean;
                true
            }
            None => false,
        },
        _ => false,
    }
}

/// The JSON object `params`, as a scan or an operation keeps it: with every credential
/// taken out (headers that carry one, cookies, tokens, passwords, API keys, and a user
/// and password in a URL) and, when there was one, `"secrets_removed": true`, so that
/// whoever takes the scan up again knows to give them again. Parameters that are not a
/// JSON object are not kept at all.
pub fn without_secrets(params: &str) -> String {
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(params) else {
        return "{}".to_string();
    };
    if strip(&mut value)
        && let serde_json::Value::Object(map) = &mut value
    {
        map.insert("secrets_removed".to_string(), serde_json::Value::Bool(true));
    }
    match value {
        serde_json::Value::Object(_) => value.to_string(),
        _ => "{}".to_string(),
    }
}

/// Start a scan of `target` with the settings `params`, a JSON object kept without its
/// credentials (see [`without_secrets`]), whose hash is `config_hash`. Unless `fresh` is set, the latest scan with the same hash that stopped
/// before its end is taken up again, and taken so that no other request takes it too; a
/// scan that is still running is never taken. Otherwise, or when there is none, a new
/// scan is made. Either way the scan is running when this returns.
pub async fn start(
    pool: &PgPool,
    target: &str,
    config_hash: &str,
    params: &str,
    fresh: bool,
) -> Result<Started, sqlx::Error> {
    if !fresh {
        let stopped: Option<String> = sqlx::query_scalar(
            "UPDATE scans SET status = 'running', updated_at = now() WHERE id = (
                SELECT id FROM scans WHERE config_hash = $1 AND status = 'stopped'
                ORDER BY updated_at DESC LIMIT 1 FOR UPDATE SKIP LOCKED
            ) RETURNING id",
        )
        .bind(config_hash)
        .fetch_optional(pool)
        .await?;
        if let Some(id) = stopped {
            return Ok(Started { id, resumed: true });
        }
    }
    let id: String = sqlx::query_scalar(
        "INSERT INTO scans (target, config_hash, params, status) \
         VALUES ($1, $2, $3::jsonb, 'running') RETURNING id",
    )
    .bind(target)
    .bind(config_hash)
    .bind(without_secrets(params))
    .fetch_one(pool)
    .await?;
    Ok(Started { id, resumed: false })
}

/// Say where scan `id` ended.
pub async fn finish(pool: &PgPool, id: &str, status: Status) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE scans SET status = $2, updated_at = now() WHERE id = $1")
        .bind(id)
        .bind(status.as_str())
        .execute(pool)
        .await?;
    Ok(())
}

/// Mark what was queued or running when the daemon last exited as stopped, so that it can
/// be taken up again. A daemon calls this as it starts, before it takes any request.
pub async fn stopped_by_exit(pool: &PgPool) -> Result<(), sqlx::Error> {
    for table in ["scans", "operations"] {
        sqlx::query(&format!(
            "UPDATE {table} SET status = 'stopped', updated_at = now() \
             WHERE status IN ('queued', 'running')"
        ))
        .execute(pool)
        .await?;
    }
    Ok(())
}

/// A line for scan `scan`'s log, or the daemon's own when `scan` is None.
pub async fn log(
    pool: &PgPool,
    scan: Option<&str>,
    level: &str,
    message: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO logs (scan_id, level, message) VALUES ($1, $2, $3)")
        .bind(scan)
        .bind(level)
        .bind(message)
        .execute(pool)
        .await?;
    Ok(())
}

/// Keep operation `id`, an `operation` sent with `params`, a JSON object kept without its
/// credentials, as queued. The same id sent again starts over.
pub async fn record_operation(
    pool: &PgPool,
    id: &str,
    operation: &str,
    scan: Option<&str>,
    params: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO operations (id, operation, scan_id, params) VALUES ($1, $2, $3, $4::jsonb) \
         ON CONFLICT (id) DO UPDATE SET operation = $2, scan_id = $3, params = $4::jsonb, \
         status = 'queued', result = NULL, updated_at = now()",
    )
    .bind(id)
    .bind(operation)
    .bind(scan)
    .bind(without_secrets(params))
    .execute(pool)
    .await?;
    Ok(())
}

/// Say where operation `id` ended, and what it gave when that is worth keeping.
pub async fn finish_operation(
    pool: &PgPool,
    id: &str,
    status: Status,
    result: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE operations SET status = $2, result = $3, updated_at = now() WHERE id = $1")
        .bind(id)
        .bind(status.as_str())
        .bind(result)
        .execute(pool)
        .await?;
    Ok(())
}

/// Empty every table in the schema of engine `engine`, keeping the tables.
pub async fn reset(pool: &PgPool, engine: &str) -> Result<(), sqlx::Error> {
    let tables: Vec<String> =
        sqlx::query_scalar("SELECT tablename FROM pg_tables WHERE schemaname = $1")
            .bind(engine)
            .fetch_all(pool)
            .await?;
    if tables.is_empty() {
        return Ok(());
    }
    let quote = |name: &str| format!("\"{}\"", name.replace('"', "\"\""));
    let list = tables
        .iter()
        .map(|t| format!("{}.{}", quote(engine), quote(t)))
        .collect::<Vec<_>>()
        .join(", ");
    sqlx::query(&format!("TRUNCATE TABLE {list} RESTART IDENTITY CASCADE"))
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ready::ready_in;
    use crate::ready::tests::{engine_at, free_port, local_on, toolchain_with};
    use crate::{Stop, ThisAccount, Toolchain};

    #[test]
    fn credentials_are_taken_out_of_what_is_kept_and_their_place_is_marked() {
        let asked = serde_json::json!({
            "endpoint": "https://user:hunter2@app.example/login?x=1",
            "auth": {"headers": {"X-Api-Key": "k-123"}, "cookies": "sid=abc"},
            "headers": ["Accept: text/html", "Authorization: Bearer t-456", "cookie: a=b"],
            "custom": {"Set-Cookie": "s=1", "keep": "this", "api_key": "k-789"},
            "list": [{"password": "p-1", "name": "n"}],
            "identify": "team-7",
            "tasks": 4,
        });
        let kept: serde_json::Value =
            serde_json::from_str(&without_secrets(&asked.to_string())).unwrap();
        assert_eq!(
            kept,
            serde_json::json!({
                "endpoint": "https://app.example/login?x=1",
                "headers": ["Accept: text/html"],
                "custom": {"keep": "this"},
                "list": [{"name": "n"}],
                "identify": "team-7",
                "tasks": 4,
                "secrets_removed": true,
            })
        );
        for secret in [
            "hunter2", "k-123", "abc", "t-456", "a=b", "s=1", "k-789", "p-1",
        ] {
            assert!(!kept.to_string().contains(secret), "{secret} was kept");
        }
        let plain = serde_json::json!({"domain": "example.com", "tasks": 4}).to_string();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&without_secrets(&plain)).unwrap(),
            serde_json::json!({"domain": "example.com", "tasks": 4}),
            "nothing to take out, nothing marked"
        );
    }

    async fn status(pool: &PgPool, id: &str) -> String {
        sqlx::query_scalar("SELECT status FROM scans WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    #[ignore = "needs PostgreSQL's programs"]
    async fn the_same_scan_twice_at_once_is_two_scans_and_a_stopped_one_is_taken_up_once() {
        let (_dir, toolchain) = toolchain_with(&local_on(free_port()));
        let pool = ready_in(toolchain.clone(), &engine_at("0.0.1", &[]))
            .await
            .unwrap();
        let (a, b) = tokio::join!(
            start(&pool, "example.com", "h", "{}", false),
            start(&pool, "example.com", "h", "{}", false),
        );
        let (a, b) = (a.unwrap(), b.unwrap());
        assert_ne!(a.id, b.id, "a running scan is never taken");
        assert!(!a.resumed && !b.resumed);

        finish(&pool, &a.id, Status::Stopped).await.unwrap();
        let c = start(&pool, "example.com", "h", "{}", false).await.unwrap();
        assert_eq!(
            c,
            Started {
                id: a.id.clone(),
                resumed: true
            }
        );
        assert_eq!(status(&pool, &a.id).await, "running");
        let d = start(&pool, "example.com", "h", "{}", false).await.unwrap();
        assert!(!d.resumed && d.id != a.id, "it is taken up once");

        finish(&pool, &d.id, Status::Stopped).await.unwrap();
        let e = start(&pool, "example.com", "h", "{}", true).await.unwrap();
        assert!(!e.resumed && e.id != d.id, "a fresh start makes a new scan");
        assert_eq!(status(&pool, &d.id).await, "stopped");

        pool.close().await;
        let account = ThisAccount::new().unwrap();
        assert_eq!(
            Toolchain::new(toolchain, &account).stop().unwrap(),
            Stop::Stopped
        );
    }

    #[tokio::test]
    #[ignore = "needs PostgreSQL's programs"]
    async fn what_ran_when_the_daemon_exited_is_stopped_and_a_reset_empties_the_schema() {
        let (_dir, toolchain) = toolchain_with(&local_on(free_port()));
        let pool = ready_in(toolchain.clone(), &engine_at("0.0.1", &[]))
            .await
            .unwrap();
        let running = start(&pool, "a", "1", "{}", false).await.unwrap();
        let done = start(&pool, "b", "2", "{}", false).await.unwrap();
        finish(&pool, &done.id, Status::Completed).await.unwrap();
        record_operation(&pool, "op", "scan", Some(&running.id), "{}")
            .await
            .unwrap();
        log(&pool, Some(&running.id), "info", "a line")
            .await
            .unwrap();

        stopped_by_exit(&pool).await.unwrap();
        assert_eq!(status(&pool, &running.id).await, "stopped");
        assert_eq!(status(&pool, &done.id).await, "completed");
        let op: String = sqlx::query_scalar("SELECT status FROM operations WHERE id = 'op'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(op, "stopped");

        reset(&pool, "cfx_db_test").await.unwrap();
        for table in ["scans", "logs", "operations"] {
            let n: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
                .fetch_one(&pool)
                .await
                .unwrap();
            assert_eq!(n, 0, "{table}");
        }
        pool.close().await;
        let account = ThisAccount::new().unwrap();
        assert_eq!(
            Toolchain::new(toolchain, &account).stop().unwrap(),
            Stop::Stopped
        );
    }
}

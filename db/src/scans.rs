//! The tables every engine has (`scans`, `logs` and `operations`), written the same way
//! by each, on a pool [`crate::ensure_ready`] gave it, which looks in the engine's own
//! schema. Nothing kept here holds a credential: see [`without_secrets`].

use sqlx::{Connection, PgPool};

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

/// Parts of a name that mark what it holds as a credential: a key, a header or a query
/// parameter whose name, in lower case, contains one of them. A harmless setting whose
/// name happens to contain one is not kept either.
const SECRET_PARTS: &[&str] = &[
    "token",
    "secret",
    "passw",
    "auth",
    "apikey",
    "api_key",
    "session",
    "credential",
    "cookie",
    "jwt",
    "csrf",
    "xsrf",
    "signature",
];

/// Query parameters that carry a credential under a name too short to look for inside
/// other names.
const SECRET_PARAMS: &[&str] = &["sig", "key", "code", "pass", "pwd"];

/// Whether `name`, a key, a header or a query parameter, names a credential (see
/// [`SECRET_PARTS`]).
pub fn secret_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    SECRET_PARTS.iter().any(|part| name.contains(part))
}

/// `url` without a user or password in it, and without the value of any query parameter
/// that carries a credential. Text that is not a URL comes back as it was.
pub fn safe_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let (before, fragment) = match tail.split_once('#') {
        Some((before, fragment)) => (before, Some(fragment)),
        None => (tail, None),
    };
    let tail = match before.split_once('?') {
        Some((path, query)) => {
            let query = query
                .split('&')
                .map(|pair| match pair.split_once('=') {
                    Some((name, _))
                        if secret_name(name)
                            || SECRET_PARAMS.contains(&name.to_ascii_lowercase().as_str()) =>
                    {
                        format!("{name}=")
                    }
                    _ => pair.to_string(),
                })
                .collect::<Vec<_>>()
                .join("&");
            format!("{path}?{query}")
        }
        None => before.to_string(),
    };
    match fragment {
        Some(fragment) => format!("{scheme}://{host}{tail}#{fragment}"),
        None => format!("{scheme}://{host}{tail}"),
    }
}

/// Text to keep, such as a log line or a result: every URL in it made safe (see
/// [`safe_url`]), and the value of a header it echoes that carries a credential left out.
pub fn safe_text(text: &str) -> String {
    text.lines()
        .map(|line| {
            if let Some((name, _)) = line.split_once(':')
                && !name.trim().contains(' ')
                && !name.contains("//")
                && secret_name(name.trim())
            {
                return format!("{name}: [not kept]");
            }
            line.split(' ')
                .map(|word| {
                    if word.contains("://") {
                        // Punctuation after a URL, as in "(url)" or "url,", is not part of it.
                        let url = word.trim_end_matches([')', ']', '>', ',', '.', ';', '"', '\'']);
                        format!("{}{}", safe_url(url), &word[url.len()..])
                    } else {
                        word.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Whether the key `key` holds headers, whose values are never kept.
fn header_key(key: &str) -> bool {
    key.to_ascii_lowercase().contains("header")
}

/// The names of headers in `value`, an object of name to value or a list of
/// `Name: value` lines, without their values. Says whether there was a value to drop.
fn header_names(value: &mut serde_json::Value) -> bool {
    use serde_json::Value;
    let (names, had_values): (Vec<String>, bool) = match value {
        Value::Object(map) => (
            map.keys().cloned().collect(),
            map.values().any(|v| v.as_str() != Some("")),
        ),
        Value::Array(lines) => {
            let mut had = false;
            let names = lines
                .iter()
                .filter_map(|line| line.as_str())
                .map(|line| match line.split_once(':') {
                    Some((name, value)) => {
                        had |= !value.trim().is_empty();
                        name.trim().to_string()
                    }
                    None => line.trim().to_string(),
                })
                .collect();
            (names, had)
        }
        _ => return false,
    };
    *value = Value::Array(names.into_iter().map(Value::String).collect());
    had_values
}

/// Whether `value`, kept under a credential's name, holds one. A null, an empty value and
/// a flag hold none.
fn holds_credential(value: &serde_json::Value) -> bool {
    use serde_json::Value;
    match value {
        Value::Null | Value::Bool(_) => false,
        Value::String(text) => !text.is_empty(),
        Value::Number(_) => true,
        Value::Array(items) => items.iter().any(holds_credential),
        Value::Object(map) => map.values().any(holds_credential),
    }
}

/// Take every credential out of `value`, and say whether there was one.
fn strip(value: &mut serde_json::Value) -> bool {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            let mut removed = false;
            map.retain(|key, v| {
                let secret = secret_name(key);
                removed |= secret && holds_credential(v);
                !secret
            });
            for (key, v) in map.iter_mut() {
                removed |= if header_key(key) {
                    header_names(v)
                } else {
                    strip(v)
                };
            }
            removed
        }
        Value::Array(items) => items
            .iter_mut()
            .fold(false, |removed, v| strip(v) | removed),
        Value::String(text) if text.contains("://") => {
            let safe = safe_url(text);
            let changed = safe != *text;
            *text = safe;
            changed
        }
        _ => false,
    }
}

/// `value`, a result such as a finding, with no credential in it: taken out as
/// [`without_secrets`] takes them out of settings, with no mark where one was.
pub fn safe_json(value: &serde_json::Value) -> serde_json::Value {
    let mut value = value.clone();
    strip(&mut value);
    value
}

/// Whether `params`, a JSON object, carries a credential [`without_secrets`] takes out: a
/// value under a credential's name, a header's value, or a URL's userinfo or secret query
/// value. A scan asked for with one authenticates to its target, so its key is
/// [`Key::Authenticated`].
pub fn carries_credentials(params: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(params)
        .map(|mut value| strip(&mut value))
        .unwrap_or(false)
}

/// The JSON object `params`, as a scan or an operation keeps it: with no credential in
/// it. Keys whose names mark a credential (see [`SECRET_PARTS`]) are left out, headers
/// keep their names and not their values, and URLs are made safe (see [`safe_url`]).
/// When a credential was taken out, `"withheld": true` says so, so that whoever takes
/// the scan up again knows to give them again. Parameters that are not a JSON object are
/// not kept at all.
pub fn without_secrets(params: &str) -> String {
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(params) else {
        return "{}".to_string();
    };
    if strip(&mut value)
        && let serde_json::Value::Object(map) = &mut value
    {
        map.insert("withheld".to_string(), serde_json::Value::Bool(true));
    }
    match value {
        serde_json::Value::Object(_) => value.to_string(),
        _ => "{}".to_string(),
    }
}

/// What a scan is known by when another request asks for the same scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key<'a> {
    /// The hash of its settings, none of them a credential: a stopped scan with the same
    /// hash is taken up again.
    Settings(&'a str),
    /// It authenticates to its target, so it is known by its id alone. A credential
    /// changes what the target answers, so such a scan never takes up another, with or
    /// without credentials, and is never taken up by one; and nothing derived from a
    /// credential is kept, a hash included. Resuming one is by its id, with its
    /// credentials given again. A credential that does not change who the target sees,
    /// such as a passive source's API key, does not count.
    Authenticated,
}

/// A scan this daemon runs. It holds the scan's lock on a connection of its own until
/// [`finish`] ends it, so that no other daemon on the same database takes the scan up and
/// another's start-up sweep leaves it running. When the daemon dies, the lock goes with
/// the connection.
pub struct Running {
    pub id: String,
    /// Whether it is a stopped scan taken up again, rather than a new one.
    pub resumed: bool,
    lock: sqlx::PgConnection,
}

/// The advisory lock a running scan's daemon holds, as SQL on the scan id `$1`.
const SCAN_LOCK: &str = "hashtextextended($1, 0)";

/// Start a scan of `target` with the settings `params`, a JSON object, known by `key`.
/// The target and the settings are kept without their credentials (see [`safe_text`] and
/// [`without_secrets`]). Unless `fresh` is set, a scan with the same [`Key::Settings`]
/// that stopped before its end is taken up again, the latest first, and so is one still
/// marked running whose daemon is gone; one whose daemon still runs it is never taken.
/// Otherwise, or when there is none, a new scan is made. Either way the scan is running
/// when this returns, and this daemon holds it.
pub async fn start(
    pool: &PgPool,
    target: &str,
    key: Key<'_>,
    params: &str,
    fresh: bool,
) -> Result<Running, sqlx::Error> {
    let mut lock = pool.acquire().await?.detach();
    if let (Key::Settings(hash), false) = (key, fresh) {
        let candidates: Vec<String> = sqlx::query_scalar(
            "SELECT id FROM scans WHERE config_hash = $1 AND status IN ('stopped', 'running') \
             ORDER BY updated_at DESC",
        )
        .bind(hash)
        .fetch_all(&mut lock)
        .await?;
        for id in candidates {
            let ours: bool =
                sqlx::query_scalar(&format!("SELECT pg_try_advisory_lock({SCAN_LOCK})"))
                    .bind(&id)
                    .fetch_one(&mut lock)
                    .await?;
            if !ours {
                continue;
            }
            let taken = sqlx::query(
                "UPDATE scans SET status = 'running', updated_at = now() \
                 WHERE id = $1 AND status IN ('stopped', 'running')",
            )
            .bind(&id)
            .execute(&mut lock)
            .await?
            .rows_affected()
                == 1;
            if taken {
                return Ok(Running {
                    id,
                    resumed: true,
                    lock,
                });
            }
            sqlx::query(&format!("SELECT pg_advisory_unlock({SCAN_LOCK})"))
                .bind(&id)
                .execute(&mut lock)
                .await?;
        }
    }
    // Held before the scan is there to be seen, so no sweep ever finds it unheld.
    let id: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(&mut lock)
        .await?;
    sqlx::query(&format!("SELECT pg_advisory_lock({SCAN_LOCK})"))
        .bind(&id)
        .execute(&mut lock)
        .await?;
    let hash = match key {
        Key::Settings(hash) => Some(hash),
        Key::Authenticated => None,
    };
    sqlx::query(
        "INSERT INTO scans (id, target, config_hash, params, status) \
         VALUES ($1, $2, $3, $4::jsonb, 'running')",
    )
    .bind(&id)
    .bind(safe_text(target))
    .bind(hash)
    .bind(without_secrets(params))
    .execute(&mut lock)
    .await?;
    Ok(Running {
        id,
        resumed: false,
        lock,
    })
}

/// Say where scan `running` ended, and let it go.
pub async fn finish(running: Running, status: Status) -> Result<(), sqlx::Error> {
    let Running { id, mut lock, .. } = running;
    let done = sqlx::query("UPDATE scans SET status = $2, updated_at = now() WHERE id = $1")
        .bind(&id)
        .bind(status.as_str())
        .execute(&mut lock)
        .await;
    let _ = lock.close().await;
    done.map(|_| ())
}

/// Mark as stopped what was queued or running when its daemon exited, so that it can be
/// taken up again: a scan whose lock nobody holds, and the operations it ran. A daemon
/// calls this as it starts, before it takes any request. A scan another daemon on the same
/// database is running is left as it is.
pub async fn stop_abandoned(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let stopped = sqlx::query(&format!(
        "UPDATE scans SET status = 'stopped', updated_at = now() \
         WHERE status IN ('queued', 'running') \
         AND pg_try_advisory_xact_lock({})",
        SCAN_LOCK.replace("$1", "id")
    ))
    .execute(&mut *tx)
    .await?
    .rows_affected();
    sqlx::query(
        "UPDATE operations o SET status = 'stopped', updated_at = now() FROM scans s \
         WHERE o.scan_id = s.id AND s.status = 'stopped' AND o.status IN ('queued', 'running')",
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(stopped)
}

/// A line for scan `scan`'s log, or the daemon's own when `scan` is None, kept without
/// credentials (see [`safe_text`]).
pub async fn log(
    pool: &PgPool,
    scan: Option<&str>,
    level: &str,
    message: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO logs (scan_id, level, message) VALUES ($1, $2, $3)")
        .bind(scan)
        .bind(level)
        .bind(safe_text(message))
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

/// Say where operation `id` ended, and what it gave when that is worth keeping: a JSON
/// result kept as [`without_secrets`] keeps settings, other text as [`safe_text`] does.
pub async fn finish_operation(
    pool: &PgPool,
    id: &str,
    status: Status,
    result: Option<&str>,
) -> Result<(), sqlx::Error> {
    let result = result.map(|r| match serde_json::from_str::<serde_json::Value>(r) {
        Ok(mut value) => {
            strip(&mut value);
            value.to_string()
        }
        Err(_) => safe_text(r),
    });
    sqlx::query("UPDATE operations SET status = $2, result = $3, updated_at = now() WHERE id = $1")
        .bind(id)
        .bind(status.as_str())
        .bind(result)
        .execute(pool)
        .await?;
    Ok(())
}

/// Which scans to delete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purge<'a> {
    /// The scan with this id.
    Scan(&'a str),
    /// Every scan made more than this many days ago.
    OlderThanDays(u32),
}

/// Delete the scans `which` names, with everything kept for them, on `conn`, which looks
/// in an engine's schema, and say how many went. A running scan is never deleted.
pub async fn purge(conn: &mut sqlx::PgConnection, which: Purge<'_>) -> Result<u64, sqlx::Error> {
    let deleted = match which {
        Purge::Scan(id) => {
            sqlx::query("DELETE FROM scans WHERE id = $1 AND status <> 'running'")
                .bind(id)
                .execute(&mut *conn)
                .await?
        }
        Purge::OlderThanDays(days) => {
            sqlx::query(
                "DELETE FROM scans WHERE status <> 'running' \
                 AND created_at < now() - make_interval(days => $1)",
            )
            .bind(days as i32)
            .execute(&mut *conn)
            .await?
        }
    };
    Ok(deleted.rows_affected())
}

/// A `purge` operation sent to an engine's daemon: `params` name a `scan` by its id, or
/// `older_than_days`. The reply's message on success, or why it did nothing.
pub async fn purge_operation(pool: &PgPool, params: &serde_json::Value) -> Result<String, String> {
    let which = match (params["scan"].as_str(), params["older_than_days"].as_u64()) {
        (Some(id), None) => Purge::Scan(id),
        (None, Some(days)) => Purge::OlderThanDays(
            u32::try_from(days).map_err(|_| format!("{days} days is more than a purge takes"))?,
        ),
        _ => return Err("a purge names one scan or a number of days".to_string()),
    };
    let mut conn = pool.acquire().await.map_err(|e| e.to_string())?;
    let deleted = purge(&mut conn, which).await.map_err(|e| e.to_string())?;
    match which {
        Purge::Scan(id) if deleted == 0 => Err(format!(
            "there is no scan {id}, or it is running, which a purge leaves alone"
        )),
        Purge::Scan(id) => Ok(format!("Deleted scan {id}.")),
        Purge::OlderThanDays(days) => Ok(format!(
            "Deleted {deleted} scan(s) made more than {days} day(s) ago."
        )),
    }
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
            "endpoint": "https://user:hunter2@app.example/login?x=1&token=t-1&sig=s-1",
            "auth": {"headers": {"X-Api-Key": "k-123"}, "cookies": "sid=abc"},
            "headers": ["Accept: text/html", "Authorization: Bearer t-456", "X-Auth-Token: t-2"],
            "extra_headers": {"Private-Token": "p-2", "X-CSRF-Token": "c-1"},
            "custom": {"Set-Cookie": "s=1", "keep": "this", "api_key": "k-789", "jwt": "j-1"},
            "list": [{"password": "p-1", "name": "n"}],
            "identify": "team-7",
            "tasks": 4,
        });
        let kept: serde_json::Value =
            serde_json::from_str(&without_secrets(&asked.to_string())).unwrap();
        assert_eq!(
            kept,
            serde_json::json!({
                "endpoint": "https://app.example/login?x=1&token=&sig=",
                "headers": ["Accept", "Authorization", "X-Auth-Token"],
                "extra_headers": ["Private-Token", "X-CSRF-Token"],
                "custom": {"keep": "this"},
                "list": [{"name": "n"}],
                "identify": "team-7",
                "tasks": 4,
                "withheld": true,
            })
        );
        for secret in [
            "hunter2", "t-1", "s-1", "k-123", "abc", "t-456", "t-2", "p-2", "c-1", "s=1", "k-789",
            "j-1", "p-1",
        ] {
            assert!(!kept.to_string().contains(secret), "{secret} was kept");
        }
        assert_eq!(
            without_secrets(&kept.to_string()),
            kept.to_string(),
            "what is kept is kept again as it is, its mark included"
        );
        let plain = serde_json::json!({"domain": "example.com", "tasks": 4}).to_string();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&without_secrets(&plain)).unwrap(),
            serde_json::json!({"domain": "example.com", "tasks": 4}),
            "nothing to take out, nothing marked"
        );
    }

    #[test]
    fn a_null_an_empty_value_or_a_flag_under_a_credentials_name_is_no_credential() {
        let none = serde_json::json!({
            "target": "https://app.example/",
            "auth": null,
            "api_key": "",
            "auth_checks": true,
            "session": {"cookies": []},
        });
        assert!(!carries_credentials(&none.to_string()));
        assert!(!without_secrets(&none.to_string()).contains("withheld"));
        for one in [
            serde_json::json!({"auth": {"headers": {"Authorization": "Bearer t-1"}}}),
            serde_json::json!({"password": 1234}),
            serde_json::json!({"target": "https://u:p@app.example/"}),
            serde_json::json!({"target": "https://app.example/?token=t-1"}),
            serde_json::json!({"headers": ["X-Forwarded-For: 10.0.0.1"]}),
        ] {
            assert!(carries_credentials(&one.to_string()), "{one}");
        }
    }

    #[test]
    fn a_result_is_kept_with_no_credential_and_no_mark_so_keeping_it_again_changes_nothing() {
        let found = serde_json::json!({
            "name": "Exposed .git",
            "matched_at": "https://u:p@app.example/.git/config?token=t-1",
            "request": {"headers": {"Cookie": "sid=s-1"}, "session": "s-2"},
        });
        let kept = safe_json(&found);
        assert_eq!(
            kept,
            serde_json::json!({
                "name": "Exposed .git",
                "matched_at": "https://app.example/.git/config?token=",
                "request": {"headers": ["Cookie"]},
            })
        );
        assert_eq!(safe_json(&kept), kept);
    }

    #[test]
    fn a_log_line_keeps_no_userinfo_query_token_or_echoed_credential() {
        assert_eq!(
            safe_text("[200] FOUND https://u:p@app.example/a?access_token=x1&q=2#f"),
            "[200] FOUND https://app.example/a?access_token=&q=2#f"
        );
        assert_eq!(
            safe_text("error sending request for url (http://app.example/a?token=x1)"),
            "error sending request for url (http://app.example/a?token=)"
        );
        assert_eq!(safe_text("Set-Cookie: sid=abc"), "Set-Cookie: [not kept]");
        assert_eq!(safe_text("x-session-id: 42"), "x-session-id: [not kept]");
        assert_eq!(safe_text("Server: nginx"), "Server: nginx");
        assert_eq!(safe_text("example.com"), "example.com");
    }

    async fn status(pool: &PgPool, id: &str) -> String {
        sqlx::query_scalar("SELECT status FROM scans WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    /// A local database of a test's own, and a pool on a schema in it.
    async fn database() -> (tempfile::TempDir, std::path::PathBuf, PgPool) {
        let (dir, toolchain) = toolchain_with(&local_on(free_port()));
        let pool = ready_in(toolchain.clone(), &engine_at("0.0.1", &[]))
            .await
            .unwrap();
        (dir, toolchain, pool)
    }

    async fn done(toolchain: std::path::PathBuf, pool: PgPool) {
        pool.close().await;
        let account = ThisAccount::new().unwrap();
        assert_eq!(
            Toolchain::new(toolchain, &account).stop().unwrap(),
            Stop::Stopped
        );
    }

    #[tokio::test]
    #[ignore = "needs PostgreSQL's programs"]
    async fn the_same_scan_twice_at_once_is_two_scans_and_a_stopped_one_is_taken_up_once() {
        let (_dir, toolchain, pool) = database().await;
        let key = Key::Settings("h");
        let (a, b) = tokio::join!(
            start(&pool, "example.com", key, "{}", false),
            start(&pool, "example.com", key, "{}", false),
        );
        let (a, b) = (a.unwrap(), b.unwrap());
        assert_ne!(a.id, b.id, "a running scan is never taken");
        assert!(!a.resumed && !b.resumed);

        let first = a.id.clone();
        finish(a, Status::Stopped).await.unwrap();
        let c = start(&pool, "example.com", key, "{}", false).await.unwrap();
        assert!(c.resumed && c.id == first, "the stopped one is taken up");
        assert_eq!(status(&pool, &first).await, "running");
        let d = start(&pool, "example.com", key, "{}", false).await.unwrap();
        assert!(!d.resumed && d.id != first, "and taken up once");

        let fourth = d.id.clone();
        finish(d, Status::Stopped).await.unwrap();
        let e = start(&pool, "example.com", key, "{}", true).await.unwrap();
        assert!(
            !e.resumed && e.id != fourth,
            "a fresh start makes a new scan"
        );
        assert_eq!(status(&pool, &fourth).await, "stopped");
        for running in [b, c, e] {
            finish(running, Status::Completed).await.unwrap();
        }
        done(toolchain, pool).await;
    }

    #[tokio::test]
    #[ignore = "needs PostgreSQL's programs"]
    async fn a_scan_with_credentials_is_never_taken_up_by_another_and_keeps_no_key() {
        let (_dir, toolchain, pool) = database().await;
        // Anonymous, stopped; then the same with credentials: a new scan.
        let anonymous = start(&pool, "a.example", Key::Settings("a"), "{}", false)
            .await
            .unwrap();
        let anonymous_id = anonymous.id.clone();
        finish(anonymous, Status::Stopped).await.unwrap();
        let with = start(&pool, "a.example", Key::Authenticated, "{}", false)
            .await
            .unwrap();
        assert!(!with.resumed && with.id != anonymous_id);
        let with_id = with.id.clone();
        finish(with, Status::Stopped).await.unwrap();

        // Authenticated, stopped; then the same anonymously: the anonymous one is taken,
        // never the authenticated one.
        let again = start(&pool, "a.example", Key::Settings("a"), "{}", false)
            .await
            .unwrap();
        assert!(again.resumed && again.id == anonymous_id);
        finish(again, Status::Completed).await.unwrap();

        // Two credentials: each its own scan, and neither takes up the stopped one.
        let one = start(&pool, "a.example", Key::Authenticated, "{}", false)
            .await
            .unwrap();
        let two = start(&pool, "a.example", Key::Authenticated, "{}", false)
            .await
            .unwrap();
        assert!(!one.resumed && !two.resumed);
        assert!(one.id != with_id && two.id != with_id && one.id != two.id);
        let keys: Vec<Option<String>> =
            sqlx::query_scalar("SELECT config_hash FROM scans WHERE id <> $1 ORDER BY created_at")
                .bind(&anonymous_id)
                .fetch_all(&pool)
                .await
                .unwrap();
        assert!(
            keys.iter().all(Option::is_none),
            "nothing derived from a credential is kept"
        );
        finish(one, Status::Completed).await.unwrap();
        finish(two, Status::Completed).await.unwrap();
        done(toolchain, pool).await;
    }

    #[tokio::test]
    #[ignore = "needs PostgreSQL's programs"]
    async fn a_daemon_starting_stops_only_the_scans_whose_daemon_is_gone() {
        let (_dir, toolchain, pool) = database().await;
        // The first daemon runs a scan; a second one starting leaves it running.
        let first = start(&pool, "a", Key::Settings("1"), "{}", false)
            .await
            .unwrap();
        let id = first.id.clone();
        assert_eq!(stop_abandoned(&pool).await.unwrap(), 0);
        assert_eq!(status(&pool, &id).await, "running");
        let other = start(&pool, "a", Key::Settings("1"), "{}", false)
            .await
            .unwrap();
        assert!(!other.resumed, "a scan its daemon runs is not taken");
        finish(other, Status::Completed).await.unwrap();

        // The first daemon is killed: its connection, and the lock, go. The next daemon
        // to start marks the scan stopped, and a request then takes it up.
        drop(first);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while stop_abandoned(&pool).await.unwrap() == 0 {
            assert!(std::time::Instant::now() < deadline, "never let go");
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert_eq!(status(&pool, &id).await, "stopped");
        let taken = start(&pool, "a", Key::Settings("1"), "{}", false)
            .await
            .unwrap();
        assert!(taken.resumed && taken.id == id);
        finish(taken, Status::Completed).await.unwrap();
        done(toolchain, pool).await;
    }

    #[tokio::test]
    #[ignore = "needs PostgreSQL's programs"]
    async fn a_purge_deletes_the_scan_it_names_or_the_old_ones_and_leaves_the_rest() {
        let (_dir, toolchain, pool) = database().await;
        let mut ids = Vec::new();
        for target in ["a", "b", "c", "d"] {
            let scan = start(&pool, target, Key::Settings(target), "{}", false)
                .await
                .unwrap();
            ids.push(scan.id.clone());
            log(&pool, Some(&scan.id), "info", target).await.unwrap();
            finish(scan, Status::Completed).await.unwrap();
        }
        let running = start(&pool, "e", Key::Settings("e"), "{}", false)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE scans SET created_at = now() - interval '40 days' WHERE target IN ('c', 'e')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let targets = |pool: PgPool| async move {
            sqlx::query_scalar::<_, String>("SELECT target FROM scans ORDER BY target")
                .fetch_all(&pool)
                .await
                .unwrap()
        };
        let mut conn = pool.acquire().await.unwrap();

        assert_eq!(purge(&mut conn, Purge::Scan(&ids[1])).await.unwrap(), 1);
        assert_eq!(targets(pool.clone()).await, ["a", "c", "d", "e"]);
        let lines: i64 = sqlx::query_scalar("SELECT count(*) FROM logs WHERE scan_id = $1")
            .bind(&ids[1])
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(lines, 0, "its log went with it");

        assert_eq!(purge(&mut conn, Purge::OlderThanDays(30)).await.unwrap(), 1);
        assert_eq!(
            targets(pool.clone()).await,
            ["a", "d", "e"],
            "c was old; e is old too, but running"
        );
        assert_eq!(purge(&mut conn, Purge::Scan(&running.id)).await.unwrap(), 0);
        drop(conn);
        finish(running, Status::Completed).await.unwrap();
        done(toolchain, pool).await;
    }

    #[tokio::test]
    #[ignore = "needs PostgreSQL's programs"]
    async fn a_reset_empties_the_schema() {
        let (_dir, toolchain, pool) = database().await;
        let scan = start(&pool, "a", Key::Settings("1"), "{}", false)
            .await
            .unwrap();
        record_operation(&pool, "op", "scan", Some(&scan.id), "{}")
            .await
            .unwrap();
        log(&pool, Some(&scan.id), "info", "a line").await.unwrap();
        finish(scan, Status::Completed).await.unwrap();
        reset(&pool, "cfx_db_test").await.unwrap();
        for table in ["scans", "logs", "operations"] {
            let n: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
                .fetch_one(&pool)
                .await
                .unwrap();
            assert_eq!(n, 0, "{table}");
        }
        done(toolchain, pool).await;
    }
}

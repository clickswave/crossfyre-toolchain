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
    clean_url(url, None)
}

/// [`safe_url`], keeping `placeholder` where it is a query parameter's whole value: what a
/// scan writes into its own URLs to be replaced, such as ambulo's fuzz marker, is no
/// credential, whatever the parameter's name.
pub fn safe_url_keeping(url: &str, placeholder: &str) -> String {
    clean_url(url, Some(placeholder))
}

fn clean_url(url: &str, placeholder: Option<&str>) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        // A path with a query, as a request line or a link gives one, has its query made
        // safe the same way.
        return match url.split_once('?') {
            Some((path, query)) if url.starts_with('/') => {
                format!("{path}?{}", clean_query(query, placeholder))
            }
            _ => url.to_string(),
        };
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
        Some((path, query)) => format!("{path}?{}", clean_query(query, placeholder)),
        None => before.to_string(),
    };
    match fragment {
        Some(fragment) => format!("{scheme}://{host}{tail}#{fragment}"),
        None => format!("{scheme}://{host}{tail}"),
    }
}

/// `query`, a URL's after its `?`, with the value of each parameter that carries a
/// credential left out, unless it is `placeholder`.
fn clean_query(query: &str, placeholder: Option<&str>) -> String {
    query
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((name, value))
                if (secret_name(name)
                    || SECRET_PARAMS.contains(&name.to_ascii_lowercase().as_str()))
                    && placeholder != Some(value) =>
            {
                format!("{name}=")
            }
            _ => pair.to_string(),
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// Text to keep, such as a log line or a result: every URL in it made safe (see
/// [`safe_url`]), and the value of a header it echoes that carries a credential left out.
pub fn safe_text(text: &str) -> String {
    clean_text(text, None)
}

fn clean_text(text: &str, placeholder: Option<&str>) -> String {
    text.lines()
        .map(|line| {
            // A header line, or one said as a header is, such as "header set-cookie: ...":
            // the name is the last word before the colon.
            if let Some((name, _)) = line.split_once(':')
                && !name.contains("//")
                && name.split_whitespace().count() <= 3
                && name.split_whitespace().next_back().is_some_and(secret_name)
            {
                return format!("{name}: [not kept]");
            }
            line.split(' ')
                .map(|word| {
                    if word.contains("://") || (word.starts_with('/') && word.contains('?')) {
                        // Punctuation after a URL, as in "(url)" or "url,", is not part of it.
                        let url = word.trim_end_matches([')', ']', '>', ',', '.', ';', '"', '\'']);
                        format!("{}{}", clean_url(url, placeholder), &word[url.len()..])
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

/// The headers in `value`, an object of name to value or a list of `Name: value` lines,
/// in the same shape with their names and none of their values, so that what is kept
/// still reads as the settings it was. Says whether there was a value to drop.
fn header_names(value: &mut serde_json::Value) -> bool {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            let had = map.values().any(|v| v.as_str() != Some(""));
            map.values_mut()
                .for_each(|v| *v = Value::String(String::new()));
            had
        }
        Value::Array(lines) => {
            let mut had = false;
            let names = lines
                .iter()
                .filter_map(|line| line.as_str())
                .map(|line| match line.split_once(':') {
                    Some((name, value)) => {
                        had |= !value.trim().is_empty();
                        Value::String(name.trim().to_string())
                    }
                    None => Value::String(line.trim().to_string()),
                })
                .collect();
            *lines = names;
            had
        }
        _ => false,
    }
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

/// Take every credential out of `value`, keeping `placeholder` in its URLs (see
/// [`safe_url_keeping`]), and say whether there was one. What a credential's name holds is
/// kept when it holds none, as a flag does.
fn strip(value: &mut serde_json::Value, placeholder: Option<&str>) -> bool {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            let mut removed = false;
            map.retain(|key, v| {
                let credential = secret_name(key) && holds_credential(v);
                removed |= credential;
                !credential
            });
            for (key, v) in map.iter_mut() {
                removed |= if header_key(key) {
                    header_names(v)
                } else {
                    strip(v, placeholder)
                };
            }
            removed
        }
        Value::Array(items) => items
            .iter_mut()
            .fold(false, |removed, v| strip(v, placeholder) | removed),
        Value::String(text) if text.contains("://") => {
            let safe = clean_url(text, placeholder);
            let changed = safe != *text;
            *text = safe;
            changed
        }
        _ => false,
    }
}

/// `event`, a line an engine sends its client, as it may leave the engine: every text in
/// it made safe as [`safe_text`] makes it, so each URL loses its userinfo and its
/// credentials' values and a header line that carries a credential loses its value, and
/// the value of a key or of a `[name, value]` pair whose name marks a credential replaced
/// with `[not kept]`. What the node relays to Cloud is what an engine sends, so this is
/// what keeps a secret in a target's URL, or in a header a scan sent, off the stream. A
/// slot a proof names in place of a value (`{{slot:...}}`) is kept, as it is none.
pub fn safe_stream(event: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    fn hidden(value: &str) -> bool {
        value.is_empty() || value.starts_with("{{slot:") || value == NOT_KEPT
    }
    fn clean(value: &mut Value) {
        match value {
            Value::String(text) => *text = safe_text(text),
            Value::Array(items) => {
                if let [Value::String(name), Value::String(held)] = items.as_mut_slice()
                    && !name.contains([' ', ':'])
                    && secret_name(name)
                    && !hidden(held)
                {
                    *held = NOT_KEPT.to_string();
                    return;
                }
                items.iter_mut().for_each(clean);
            }
            Value::Object(map) => {
                for (key, v) in map.iter_mut() {
                    match v {
                        Value::String(held) if secret_name(key) && !hidden(held) => {
                            *held = NOT_KEPT.to_string();
                        }
                        _ => clean(v),
                    }
                }
            }
            _ => {}
        }
    }
    let mut event = event.clone();
    clean(&mut event);
    event
}

/// What a credential's value is replaced with in a line an engine sends.
const NOT_KEPT: &str = "[not kept]";

/// `value`, a result such as a finding, with no credential in it: taken out as
/// [`without_secrets`] takes them out of settings, with no mark where one was.
pub fn safe_json(value: &serde_json::Value) -> serde_json::Value {
    let mut value = value.clone();
    strip(&mut value, None);
    value
}

/// Whether `params`, a JSON object, carries a credential [`without_secrets`] takes out: a
/// value under a credential's name, a header's value, or a URL's userinfo or secret query
/// value. A scan asked for with one authenticates to its target, so its key is
/// [`Key::Authenticated`].
pub fn carries_credentials(params: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(params)
        .map(|mut value| strip(&mut value, None))
        .unwrap_or(false)
}

/// The JSON object `params`, as a scan or an operation keeps it: with no credential in
/// it. A key whose name marks a credential (see [`SECRET_PARTS`]) is left out when it
/// holds one, headers keep their names and not their values, and URLs are made safe (see
/// [`safe_url`]). When a credential was taken out, `"withheld": true` says so, so that
/// whoever takes the scan up again knows to give them again. Parameters that are not a
/// JSON object are not kept at all.
pub fn without_secrets(params: &str) -> String {
    clean_params(params, None)
}

fn clean_params(params: &str, placeholder: Option<&str>) -> String {
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(params) else {
        return "{}".to_string();
    };
    if strip(&mut value, placeholder)
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
    /// Its settings, none of them a credential, or a digest of them: a stopped scan with
    /// the same is taken up again. It is kept as a digest of its own, so settings of any
    /// length can be the key.
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

/// What a request asks a scan for: what it is pointed at and its settings, a JSON object.
/// Both are kept with no credential in them (see [`safe_text`] and [`without_secrets`]).
#[derive(Debug, Clone, Copy)]
pub struct Asked<'a> {
    pub target: &'a str,
    pub params: &'a str,
    /// What the scan writes into its own URLs to be replaced, such as ambulo's fuzz
    /// marker, which is kept where a credential's value is taken out (see
    /// [`safe_url_keeping`]).
    pub placeholder: Option<&'a str>,
}

impl<'a> Asked<'a> {
    pub fn new(target: &'a str, params: &'a str) -> Self {
        Self {
            target,
            params,
            placeholder: None,
        }
    }

    /// The same, keeping `placeholder`.
    pub fn keeping(self, placeholder: &'a str) -> Self {
        Self {
            placeholder: Some(placeholder),
            ..self
        }
    }

    /// The target as it is kept.
    pub fn kept_target(&self) -> String {
        clean_text(self.target, self.placeholder)
    }

    /// The settings as they are kept.
    pub fn kept_params(&self) -> String {
        clean_params(self.params, self.placeholder)
    }
}

/// Start a scan `asked` for, known by `key`. Unless `fresh` is set, a scan with the same
/// [`Key::Settings`] that stopped before its end is taken up again, the latest first, and
/// so is one still marked running whose daemon is gone; one whose daemon still runs it is
/// never taken. Otherwise, or when there is none, a new scan is made. Either way the scan
/// is running when this returns, and this daemon holds it.
pub async fn start(
    pool: &PgPool,
    asked: Asked<'_>,
    key: Key<'_>,
    fresh: bool,
) -> Result<Running, sqlx::Error> {
    let mut lock = pool.acquire().await?.detach();
    if let (Key::Settings(hash), false) = (key, fresh) {
        let candidates: Vec<String> = sqlx::query_scalar(
            "SELECT id FROM scans WHERE config_hash = md5($1) AND status IN ('stopped', 'running') \
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
         VALUES ($1, $2, md5($3), $4::jsonb, 'running')",
    )
    .bind(&id)
    .bind(asked.kept_target())
    .bind(hash)
    .bind(asked.kept_params())
    .execute(&mut lock)
    .await?;
    Ok(Running {
        id,
        resumed: false,
        lock,
    })
}

/// Why a scan could not be taken up again by its id.
#[derive(Debug)]
pub enum NotTaken {
    Unknown(String),
    /// It ran to its end, with the status it ended with.
    Ended(String, &'static str),
    /// A daemon runs it.
    Running(String),
    /// It was given credentials, which were not kept, so it can be taken up only by a
    /// request that gives them again.
    Withheld(String),
    /// The request taking it up asked for it with settings other than its own.
    OtherSettings(String),
    Database(sqlx::Error),
}

impl std::fmt::Display for NotTaken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotTaken::Unknown(id) => write!(f, "there is no scan {id}"),
            NotTaken::Ended(id, status) => {
                write!(f, "scan {id} cannot be taken up again: it is {status}")
            }
            NotTaken::Running(id) => write!(f, "scan {id} is running"),
            NotTaken::Withheld(id) => write!(
                f,
                "scan {id} was given credentials, which are not kept: ask for it as it was \
                 first asked for, credentials included, with its id to take it up"
            ),
            NotTaken::OtherSettings(id) => write!(
                f,
                "scan {id} was asked for with other settings: ask for it as it was first \
                 asked for to take it up"
            ),
            NotTaken::Database(e) => write!(f, "{e}"),
        }
    }
}

impl From<sqlx::Error> for NotTaken {
    fn from(e: sqlx::Error) -> Self {
        NotTaken::Database(e)
    }
}

/// Take stopped scan `id` up again, and give its settings as they were kept. A scan
/// still marked running whose daemon is gone counts as stopped. With `given`, the request
/// gave the settings again, credentials included, and they must be the ones the scan
/// was kept with. Without, the scan runs with the settings it was kept with, which it
/// cannot when credentials were taken out of them.
pub async fn take_up(
    pool: &PgPool,
    id: &str,
    given: Option<Asked<'_>>,
) -> Result<(Running, serde_json::Value), NotTaken> {
    let mut lock = pool.acquire().await?.detach();
    let ours: bool = sqlx::query_scalar(&format!("SELECT pg_try_advisory_lock({SCAN_LOCK})"))
        .bind(id)
        .fetch_one(&mut lock)
        .await?;
    let kept: Option<(String, serde_json::Value)> = if ours {
        sqlx::query_as("SELECT status, params FROM scans WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut lock)
            .await?
    } else {
        None
    };
    let refused = match &kept {
        _ if !ours => Some(NotTaken::Running(id.to_string())),
        None => Some(NotTaken::Unknown(id.to_string())),
        Some((status, settings)) => refusal(id, status, settings, given),
    };
    match (refused, kept) {
        (None, Some((_, settings))) => {
            sqlx::query("UPDATE scans SET status = 'running', updated_at = now() WHERE id = $1")
                .bind(id)
                .execute(&mut lock)
                .await?;
            Ok((
                Running {
                    id: id.to_string(),
                    resumed: true,
                    lock,
                },
                settings,
            ))
        }
        (why, _) => {
            let _ = let_go(lock, ours.then_some(id)).await;
            Err(why.unwrap_or_else(|| NotTaken::Unknown(id.to_string())))
        }
    }
}

/// Why scan `id`, with `status` and the `settings` it was kept with, cannot be taken up
/// again by a request that gave its settings again (`given`) or none, or None when it can.
fn refusal(
    id: &str,
    status: &str,
    settings: &serde_json::Value,
    given: Option<Asked<'_>>,
) -> Option<NotTaken> {
    if let Some(ended) = [Status::Completed, Status::Failed]
        .into_iter()
        .find(|s| s.as_str() == status)
    {
        return Some(NotTaken::Ended(id.to_string(), ended.as_str()));
    }
    match given {
        Some(given) => {
            let asked = serde_json::from_str::<serde_json::Value>(&given.kept_params()).ok();
            (asked.as_ref() != Some(settings)).then(|| NotTaken::OtherSettings(id.to_string()))
        }
        None => (settings["withheld"] == true).then(|| NotTaken::Withheld(id.to_string())),
    }
}

/// A scan as the `scans` operation of a daemon lists it.
#[derive(Debug, Clone, PartialEq)]
pub struct Listed {
    pub id: String,
    pub target: String,
    pub status: String,
    /// When it was made and when it last changed, in RFC 3339, UTC.
    pub created_at: String,
    pub updated_at: String,
    /// Its settings as they were kept, with no credential in them.
    pub settings: serde_json::Value,
    /// How far it got, as it last said, and how many findings it kept.
    pub progress: serde_json::Value,
    pub findings: i64,
}

impl Listed {
    /// Why it cannot be taken up again from what was kept, or None when it can: only a
    /// stopped scan can be, and not one given credentials, which were not kept.
    pub fn why_not(&self) -> Option<String> {
        match self.status.as_str() {
            "stopped" if self.settings["withheld"] == true => Some(
                "it was given credentials, which are not kept: ask for it as it was first \
                 asked for, with its id"
                    .to_string(),
            ),
            "stopped" => None,
            "running" | "queued" => Some("it is running".to_string()),
            ended => Some(format!("it is {ended}")),
        }
    }

    /// As a daemon answers with it, `why_not` being why it cannot be taken up, if not.
    pub fn to_json(&self, why_not: Option<String>) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "target": self.target,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "settings": self.settings,
            "progress": self.progress,
            "findings": self.findings,
            "resumable": why_not.is_none(),
            "why_not": why_not,
        })
    }
}

/// How many scans a daemon lists, the latest first.
const LISTED: i64 = 200;

/// What a daemon answers a `scans` request with: its latest scans, each with why it
/// cannot be taken up again when it cannot, as `why_not` tells for the engine.
pub async fn answer_scans(
    pool: &PgPool,
    why_not: impl Fn(&Listed) -> Option<String>,
) -> serde_json::Value {
    match list(pool, LISTED).await {
        Ok(scans) => serde_json::json!({
            "status": "completed",
            "scans": scans.iter().map(|s| s.to_json(why_not(s))).collect::<Vec<_>>(),
        }),
        Err(e) => serde_json::json!({
            "status": "error",
            "message": format!("could not list the scans: {e}"),
        }),
    }
}

/// The latest `limit` scans, the latest first.
pub async fn list(pool: &PgPool, limit: i64) -> Result<Vec<Listed>, sqlx::Error> {
    type Row = (
        String,
        String,
        String,
        String,
        String,
        serde_json::Value,
        serde_json::Value,
        i64,
    );
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT id, target, status, \
         to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
         to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), params, \
         progress, (SELECT count(*) FROM findings f WHERE f.scan_id = s.id) \
         FROM scans s ORDER BY created_at DESC, id LIMIT $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, target, status, created_at, updated_at, settings, progress, findings)| Listed {
                id,
                target,
                status,
                created_at,
                updated_at,
                settings,
                progress,
                findings,
            },
        )
        .collect())
}

/// Say where scan `running` ended, and let it go.
pub async fn finish(running: Running, status: Status) -> Result<(), sqlx::Error> {
    let Running { id, mut lock, .. } = running;
    let done = sqlx::query("UPDATE scans SET status = $2, updated_at = now() WHERE id = $1")
        .bind(&id)
        .bind(status.as_str())
        .execute(&mut lock)
        .await;
    let released = let_go(lock, Some(&id)).await;
    done.map(|_| ()).and(released)
}

/// Close `lock`, first letting go of scan `held`'s lock when it holds it. On a closed
/// connection the server frees the lock only once it has read the close, which can be
/// after a daemon asking for the scan straight after has found it still held.
async fn let_go(mut lock: sqlx::PgConnection, held: Option<&str>) -> Result<(), sqlx::Error> {
    let released = match held {
        Some(id) => sqlx::query(&format!("SELECT pg_advisory_unlock({SCAN_LOCK})"))
            .bind(id)
            .execute(&mut lock)
            .await
            .map(|_| ()),
        None => Ok(()),
    };
    let _ = lock.close().await;
    released
}

/// Mark as stopped what was queued or running when its daemon exited, so that it can be
/// taken up again: a scan whose lock nobody holds, and the operations it ran. A daemon
/// calls this as it starts, before it takes any request. A scan another daemon on the same
/// database is running is left as it is. An operation that ran no scan has no lock to
/// tell, so it is taken for stopped once nothing has moved it for a day.
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
    sqlx::query(
        "UPDATE operations SET status = 'stopped', updated_at = now() \
         WHERE scan_id IS NULL AND status IN ('queued', 'running') \
         AND updated_at < now() - interval '1 day'",
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
            strip(&mut value, None);
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
    /// An engine's line keeps no credential: not a URL's userinfo or secret query value,
    /// not a credential header's value in a text or under a key or in a name and value
    /// pair, and a proof's slot is left as it is.
    #[test]
    fn a_line_an_engine_sends_carries_no_credential() {
        let event = serde_json::json!({"type": "finding", "data": {
            "target": "https://u:pw-secret-1@app.test/a?token=q-secret-2&page=1",
            "evidence": ["header set-cookie: session=c-secret-3", "header server: nginx"],
            "banner": "HTTP/1.1 200 OK\nSet-Cookie: sid=c-secret-4\nServer: x",
            "headers": {"Authorization": "Bearer h-secret-5", "Accept": "*/*"},
            "fields": [["X-Api-Token", "p-secret-6"], ["X-Kept", "{{slot:header.X-Kept}}"],
                       ["Cookie", "{{slot:auth.cookie}}"]],
            "count": 3,
            "auth_checks": false,
            "request": "GET /search?q=1&token=r-secret-7 HTTP/1.1",
        }});
        let safe = safe_stream(&event);
        let text = safe.to_string();
        for secret in [
            "pw-secret-1",
            "q-secret-2",
            "c-secret-3",
            "c-secret-4",
            "h-secret-5",
            "p-secret-6",
            "r-secret-7",
        ] {
            assert!(!text.contains(secret), "{secret} in {text}");
        }
        assert_eq!(safe["data"]["target"], "https://app.test/a?token=&page=1");
        assert_eq!(safe["data"]["evidence"][1], "header server: nginx");
        assert_eq!(safe["data"]["headers"]["Accept"], "*/*");
        assert_eq!(safe["data"]["fields"][1][1], "{{slot:header.X-Kept}}");
        assert_eq!(safe["data"]["fields"][2][1], "{{slot:auth.cookie}}");
        assert_eq!(safe["data"]["count"], 3);
        assert_eq!(safe["data"]["auth_checks"], false);
        let plain = serde_json::json!({"type": "progress", "processed": 2, "total": 9});
        assert_eq!(safe_stream(&plain), plain);
    }

    use super::*;
    use crate::ready::tests::engine_at;
    use crate::testing::Scratch;

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
                "extra_headers": {"Private-Token": "", "X-CSRF-Token": ""},
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
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&without_secrets(&none.to_string())).unwrap(),
            none,
            "it is kept as it was, so a scan taken up from what was kept runs as asked"
        );
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
                "request": {"headers": {"Cookie": ""}},
            })
        );
        assert_eq!(safe_json(&kept), kept);
    }

    #[test]
    fn a_scans_own_placeholder_is_kept_where_a_credential_is_taken_out() {
        let url = "https://u:p-1@app.example/api?key=::FUZZ::&token=t-1&code=x::FUZZ::";
        assert_eq!(
            safe_url_keeping(url, "::FUZZ::"),
            "https://app.example/api?key=::FUZZ::&token=&code="
        );
        assert_eq!(safe_url(url), "https://app.example/api?key=&token=&code=");
        let asked = Asked::new(
            url,
            r#"{"endpoint": "https://app.example/api?key=::FUZZ::", "auth": {"cookies": "c-1"}}"#,
        )
        .keeping("::FUZZ::");
        assert_eq!(
            asked.kept_target(),
            "https://app.example/api?key=::FUZZ::&token=&code="
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&asked.kept_params()).unwrap(),
            serde_json::json!({
                "endpoint": "https://app.example/api?key=::FUZZ::",
                "withheld": true,
            })
        );
    }

    #[test]
    fn only_a_stopped_scan_given_no_credential_is_taken_up_from_what_was_kept() {
        let scan = |status: &str, settings: serde_json::Value| Listed {
            id: "s-1".into(),
            target: "app.example".into(),
            status: status.into(),
            created_at: "2026-11-19T10:00:00Z".into(),
            updated_at: "2026-11-19T11:00:00Z".into(),
            settings,
            progress: serde_json::json!({}),
            findings: 0,
        };
        assert_eq!(scan("stopped", serde_json::json!({})).why_not(), None);
        assert!(
            scan("stopped", serde_json::json!({"withheld": true}))
                .why_not()
                .is_some_and(|why| why.contains("credentials"))
        );
        assert_eq!(
            scan("running", serde_json::json!({})).why_not().as_deref(),
            Some("it is running")
        );
        assert_eq!(
            scan("completed", serde_json::json!({}))
                .why_not()
                .as_deref(),
            Some("it is completed")
        );
        assert_eq!(
            scan("stopped", serde_json::json!({"tasks": 4})).to_json(None),
            serde_json::json!({
                "id": "s-1",
                "target": "app.example",
                "status": "stopped",
                "created_at": "2026-11-19T10:00:00Z",
                "updated_at": "2026-11-19T11:00:00Z",
                "settings": {"tasks": 4},
                "progress": {},
                "findings": 0,
                "resumable": true,
                "why_not": null,
            })
        );
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

    /// A local database of a test's own, with a schema in it for an engine with no
    /// tables but the shared ones.
    async fn database() -> Scratch {
        Scratch::new(&engine_at("0.0.1", &[])).await
    }

    /// Whether scan `id`'s lock is free: taken on `conn`, and let go at once.
    async fn free(conn: &mut sqlx::PgConnection, id: &str) -> bool {
        let free: bool = sqlx::query_scalar(&format!("SELECT pg_try_advisory_lock({SCAN_LOCK})"))
            .bind(id)
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        if free {
            sqlx::query(&format!("SELECT pg_advisory_unlock({SCAN_LOCK})"))
                .bind(id)
                .execute(&mut *conn)
                .await
                .unwrap();
        }
        free
    }

    /// A scan is let go before finish returns, and before a take-up that refused it
    /// returns, so a daemon asking for it straight after finds it free. Closing the
    /// connection alone frees it only once the server has read the close: with every
    /// core busy, after the next request had asked, about one time in three.
    #[tokio::test]
    #[ignore = "needs PostgreSQL's programs"]
    async fn a_scan_is_let_go_before_finish_or_a_refused_take_up_returns() {
        let db = database().await;
        let pool = db.pool.clone();
        let mut probe = pool.acquire().await.unwrap();
        for i in 0..100 {
            let key = format!("k{i}");
            let scan = start(
                &pool,
                Asked::new("example.com", "{}"),
                Key::Settings(&key),
                true,
            )
            .await
            .unwrap();
            let id = scan.id.clone();
            finish(scan, Status::Stopped).await.unwrap();
            assert!(free(&mut probe, &id).await, "held after finish, at {i}");
            let other = Asked::new("example.com", r#"{"tasks": 2}"#);
            assert!(matches!(
                take_up(&pool, &id, Some(other)).await,
                Err(NotTaken::OtherSettings(_))
            ));
            assert!(
                free(&mut probe, &id).await,
                "held after a refused take-up, at {i}"
            );
        }
        drop(probe);
        db.done().await;
    }

    #[tokio::test]
    #[ignore = "needs PostgreSQL's programs"]
    async fn the_same_scan_twice_at_once_is_two_scans_and_a_stopped_one_is_taken_up_once() {
        let db = database().await;
        let pool = db.pool.clone();
        let key = Key::Settings("h");
        let (a, b) = tokio::join!(
            start(&pool, Asked::new("example.com", "{}"), key, false),
            start(&pool, Asked::new("example.com", "{}"), key, false),
        );
        let (a, b) = (a.unwrap(), b.unwrap());
        assert_ne!(a.id, b.id, "a running scan is never taken");
        assert!(!a.resumed && !b.resumed);

        let first = a.id.clone();
        finish(a, Status::Stopped).await.unwrap();
        let c = start(&pool, Asked::new("example.com", "{}"), key, false)
            .await
            .unwrap();
        assert!(c.resumed && c.id == first, "the stopped one is taken up");
        assert_eq!(status(&pool, &first).await, "running");
        let d = start(&pool, Asked::new("example.com", "{}"), key, false)
            .await
            .unwrap();
        assert!(!d.resumed && d.id != first, "and taken up once");

        let fourth = d.id.clone();
        finish(d, Status::Stopped).await.unwrap();
        let e = start(&pool, Asked::new("example.com", "{}"), key, true)
            .await
            .unwrap();
        assert!(
            !e.resumed && e.id != fourth,
            "a fresh start makes a new scan"
        );
        assert_eq!(status(&pool, &fourth).await, "stopped");
        for running in [b, c, e] {
            finish(running, Status::Completed).await.unwrap();
        }
        db.done().await;
    }

    #[tokio::test]
    #[ignore = "needs PostgreSQL's programs"]
    async fn a_scan_with_credentials_is_never_taken_up_by_another_and_keeps_no_key() {
        let db = database().await;
        let pool = db.pool.clone();
        // Anonymous, stopped; then the same with credentials: a new scan.
        let anonymous = start(
            &pool,
            Asked::new("a.example", "{}"),
            Key::Settings("a"),
            false,
        )
        .await
        .unwrap();
        let anonymous_id = anonymous.id.clone();
        finish(anonymous, Status::Stopped).await.unwrap();
        let with = start(
            &pool,
            Asked::new("a.example", "{}"),
            Key::Authenticated,
            false,
        )
        .await
        .unwrap();
        assert!(!with.resumed && with.id != anonymous_id);
        let with_id = with.id.clone();
        finish(with, Status::Stopped).await.unwrap();

        // Authenticated, stopped; then the same anonymously: the anonymous one is taken,
        // never the authenticated one.
        let again = start(
            &pool,
            Asked::new("a.example", "{}"),
            Key::Settings("a"),
            false,
        )
        .await
        .unwrap();
        assert!(again.resumed && again.id == anonymous_id);
        finish(again, Status::Completed).await.unwrap();

        // Two credentials: each its own scan, and neither takes up the stopped one.
        let one = start(
            &pool,
            Asked::new("a.example", "{}"),
            Key::Authenticated,
            false,
        )
        .await
        .unwrap();
        let two = start(
            &pool,
            Asked::new("a.example", "{}"),
            Key::Authenticated,
            false,
        )
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
        db.done().await;
    }

    #[tokio::test]
    #[ignore = "needs PostgreSQL's programs"]
    async fn a_stopped_scan_is_taken_up_by_its_id_and_only_with_its_own_settings() {
        let db = database().await;
        let pool = db.pool.clone();
        let plain = Asked::new("a.example", r#"{"tasks": 4}"#);
        let scan = start(&pool, plain, Key::Settings("k"), false)
            .await
            .unwrap();
        let id = scan.id.clone();
        finish(scan, Status::Stopped).await.unwrap();
        let (taken, settings) = take_up(&pool, &id, None).await.unwrap();
        assert!(taken.resumed);
        assert_eq!(settings, serde_json::json!({"tasks": 4}));
        assert_eq!(status(&pool, &id).await, "running");
        assert!(matches!(
            take_up(&pool, &id, None).await,
            Err(NotTaken::Running(_))
        ));
        finish(taken, Status::Completed).await.unwrap();
        assert!(matches!(
            take_up(&pool, &id, None).await,
            Err(NotTaken::Ended(_, "completed"))
        ));
        assert!(matches!(
            take_up(&pool, "no-such-scan", None).await,
            Err(NotTaken::Unknown(_))
        ));

        // One given credentials: only by a request that gives them again, with the
        // settings it was asked for with.
        let with = r#"{"tasks": 4, "auth": {"cookies": "sid=c-1"}}"#;
        let scan = start(
            &pool,
            Asked::new("a.example", with),
            Key::Authenticated,
            false,
        )
        .await
        .unwrap();
        let id = scan.id.clone();
        finish(scan, Status::Stopped).await.unwrap();
        assert!(matches!(
            take_up(&pool, &id, None).await,
            Err(NotTaken::Withheld(_))
        ));
        let other = r#"{"tasks": 8, "auth": {"cookies": "sid=c-1"}}"#;
        assert!(matches!(
            take_up(&pool, &id, Some(Asked::new("a.example", other))).await,
            Err(NotTaken::OtherSettings(_))
        ));
        assert_eq!(status(&pool, &id).await, "stopped", "left as it was");
        let (taken, _) = take_up(&pool, &id, Some(Asked::new("a.example", with)))
            .await
            .unwrap();
        finish(taken, Status::Completed).await.unwrap();
        db.done().await;
    }

    #[tokio::test]
    #[ignore = "needs PostgreSQL's programs"]
    async fn settings_of_any_length_key_a_scan() {
        let db = database().await;
        let pool = db.pool.clone();
        let ports = (1..=4000)
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let key = Key::Settings(&ports);
        let first = start(&pool, Asked::new("a.example", "{}"), key, false)
            .await
            .unwrap();
        let id = first.id.clone();
        finish(first, Status::Stopped).await.unwrap();
        let again = start(&pool, Asked::new("a.example", "{}"), key, false)
            .await
            .unwrap();
        assert_eq!((again.id.as_str(), again.resumed), (id.as_str(), true));
        finish(again, Status::Completed).await.unwrap();
        db.done().await;
    }

    #[tokio::test]
    #[ignore = "needs PostgreSQL's programs"]
    async fn the_scans_are_listed_the_latest_first() {
        let db = database().await;
        let pool = db.pool.clone();
        for target in ["first.example", "second.example", "third.example"] {
            let scan = start(
                &pool,
                Asked::new(target, "{}"),
                Key::Settings(target),
                false,
            )
            .await
            .unwrap();
            finish(scan, Status::Stopped).await.unwrap();
        }
        let listed = list(&pool, 2).await.unwrap();
        assert_eq!(
            listed.iter().map(|s| s.target.as_str()).collect::<Vec<_>>(),
            ["third.example", "second.example"]
        );
        let stamp = &listed[0].created_at;
        assert!(
            stamp.len() == 20 && stamp.ends_with('Z') && stamp.as_bytes()[10] == b'T',
            "{stamp}"
        );
        assert_eq!(listed[0].status, "stopped");
        db.done().await;
    }

    #[tokio::test]
    #[ignore = "needs PostgreSQL's programs"]
    async fn an_operation_that_ran_no_scan_is_stopped_once_a_day_has_gone_without_it() {
        let db = database().await;
        let pool = db.pool.clone();
        sqlx::query(
            "INSERT INTO operations (id, operation, status, updated_at) VALUES \
             ('old', 'enum', 'running', now() - interval '25 hours'), \
             ('new', 'enum', 'running', now())",
        )
        .execute(&pool)
        .await
        .unwrap();
        stop_abandoned(&pool).await.unwrap();
        let statuses: Vec<(String, String)> =
            sqlx::query_as("SELECT id, status FROM operations ORDER BY id")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(
            statuses,
            [
                ("new".to_string(), "running".to_string()),
                ("old".to_string(), "stopped".to_string())
            ]
        );
        db.done().await;
    }

    #[tokio::test]
    #[ignore = "needs PostgreSQL's programs"]
    async fn a_daemon_starting_stops_only_the_scans_whose_daemon_is_gone() {
        let db = database().await;
        let pool = db.pool.clone();
        // The first daemon runs a scan; a second one starting leaves it running.
        let first = start(&pool, Asked::new("a", "{}"), Key::Settings("1"), false)
            .await
            .unwrap();
        let id = first.id.clone();
        assert_eq!(stop_abandoned(&pool).await.unwrap(), 0);
        assert_eq!(status(&pool, &id).await, "running");
        let other = start(&pool, Asked::new("a", "{}"), Key::Settings("1"), false)
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
        let taken = start(&pool, Asked::new("a", "{}"), Key::Settings("1"), false)
            .await
            .unwrap();
        assert!(taken.resumed && taken.id == id);
        finish(taken, Status::Completed).await.unwrap();
        db.done().await;
    }

    #[tokio::test]
    #[ignore = "needs PostgreSQL's programs"]
    async fn a_purge_deletes_the_scan_it_names_or_the_old_ones_and_leaves_the_rest() {
        let db = database().await;
        let pool = db.pool.clone();
        let mut ids = Vec::new();
        for target in ["a", "b", "c", "d"] {
            let scan = start(
                &pool,
                Asked::new(target, "{}"),
                Key::Settings(target),
                false,
            )
            .await
            .unwrap();
            ids.push(scan.id.clone());
            log(&pool, Some(&scan.id), "info", target).await.unwrap();
            finish(scan, Status::Completed).await.unwrap();
        }
        let running = start(&pool, Asked::new("e", "{}"), Key::Settings("e"), false)
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
        db.done().await;
    }

    #[tokio::test]
    #[ignore = "needs PostgreSQL's programs"]
    async fn a_reset_empties_the_schema() {
        let db = database().await;
        let pool = db.pool.clone();
        let scan = start(&pool, Asked::new("a", "{}"), Key::Settings("1"), false)
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
        db.done().await;
    }
}

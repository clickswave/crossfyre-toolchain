//! Node-side credential resolution and auth-context building.
//!
//! Workflow operations (crawl / service-enum / vuln-scan) may carry a
//! `credential_id`. When they do, the node resolves that id into a usable auth
//! context and injects it into the engine request as an `auth` object shaped:
//!
//! ```json
//! { "headers": { "Authorization": "Bearer ..." }, "cookies": "sid=..." }
//! ```
//!
//! Resolution goes through the control plane (POST /api/v1/creds/resolve), which
//! authenticates this node by its api_key, enforces workspace ownership + host
//! scope, and decrypts the secret. The node then turns the resolved credential
//! into concrete request auth:
//!
//! - static types (bearer/header/cookie/basic): built directly, no network.
//! - login_flow: the node replays the login (reqwest) and captures the resulting
//!   session token/cookie.
//! - oauth2 / sso: delegated to the control-plane broker (not yet wired here).
//!
//! Built contexts are cached per credential id (with a short TTL) so we do not
//! re-login on every request.

use base64::Engine as _;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A credential resolved from the control plane (secret decrypted).
#[derive(Clone, Debug)]
pub struct ResolvedCredential {
    pub name: String,
    pub auth_type: String,
    pub config: Value,
    pub secret: Value,
    pub scope_hosts: Vec<String>,
    /// Pre-resolved session for browser-brokered types (sso / oauth2 authcode):
    /// the control plane drove the login and returned only `{ headers, cookies }`.
    pub resolved_auth: Option<Value>,
}

/// Concrete request auth ready to attach to outbound HTTP.
#[derive(Clone, Debug, Default)]
pub struct AuthContext {
    pub headers: Vec<(String, String)>,
    pub cookies: Option<String>,
}

impl AuthContext {
    /// The `auth` object shape the engines consume.
    pub fn to_json(&self) -> Value {
        let mut hdrs = serde_json::Map::new();
        for (k, v) in &self.headers {
            hdrs.insert(k.clone(), Value::String(v.clone()));
        }
        json!({
            "headers": Value::Object(hdrs),
            "cookies": self.cookies.clone().unwrap_or_default(),
        })
    }

    pub fn is_empty(&self) -> bool {
        self.headers.is_empty() && self.cookies.as_deref().unwrap_or("").is_empty()
    }
}

// Session cache: credential_id -> (context, built_at). Login/OAuth results are
// reused for CACHE_TTL; static contexts are cheap but cached too.
static CACHE: Mutex<Option<HashMap<String, (AuthContext, Instant)>>> = Mutex::new(None);
const CACHE_TTL: Duration = Duration::from_secs(600);

fn cache_get(id: &str) -> Option<AuthContext> {
    let guard = CACHE.lock().ok()?;
    let map = guard.as_ref()?;
    let (ctx, at) = map.get(id)?;
    if at.elapsed() < CACHE_TTL {
        Some(ctx.clone())
    } else {
        None
    }
}

fn cache_put(id: &str, ctx: &AuthContext) {
    if let Ok(mut guard) = CACHE.lock() {
        let map = guard.get_or_insert_with(HashMap::new);
        map.insert(id.to_string(), (ctx.clone(), Instant::now()));
    }
}

/// Resolve a credential id into a decrypted ResolvedCredential via the control
/// plane. `host` is the target the auth is about to be sent to (scope check).
pub async fn resolve(
    http: &reqwest::Client,
    api_url: &str,
    node_api_key: &str,
    credential_id: &str,
    host: &str,
) -> Result<ResolvedCredential, String> {
    let url = format!("{}/api/v1/creds/resolve", api_url.trim_end_matches('/'));
    let resp = http
        .post(&url)
        .json(&json!({
            "api_key": node_api_key,
            "credential_id": credential_id,
            "host": host,
        }))
        .send()
        .await
        .map_err(|e| format!("resolve request failed: {e}"))?;

    let body: Value = resp
        .json()
        .await
        .map_err(|e| format!("resolve decode failed: {e}"))?;

    let status = body["status"].as_i64().unwrap_or(0);
    if status != 200 {
        let msg = body["message"].as_str().unwrap_or("resolve rejected");
        return Err(format!("resolve {status}: {msg}"));
    }
    let d = &body["data"];
    Ok(ResolvedCredential {
        name: d["name"].as_str().unwrap_or("").to_string(),
        auth_type: d["auth_type"].as_str().unwrap_or("").to_string(),
        config: d["config"].clone(),
        secret: d["secret"].clone(),
        scope_hosts: d["scope_hosts"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        resolved_auth: match &d["resolved_auth"] {
            Value::Object(_) => Some(d["resolved_auth"].clone()),
            _ => None,
        },
    })
}

/// Build an AuthContext from a pre-resolved `{ headers, cookies }` object (the
/// browser broker's output for sso / oauth2 authorization_code).
fn auth_context_from_json(v: &Value) -> AuthContext {
    let headers = v["headers"]
        .as_object()
        .map(|o| {
            o.iter()
                .filter_map(|(k, val)| val.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();
    let cookies = v["cookies"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(String::from);
    AuthContext { headers, cookies }
}

/// Build a concrete AuthContext from a resolved credential. Executes a login for
/// login_flow types; static types are built directly.
pub async fn build_context(
    http: &reqwest::Client,
    cred: &ResolvedCredential,
) -> Result<AuthContext, String> {
    match cred.auth_type.as_str() {
        "bearer" => {
            let token = cred.secret["token"].as_str().unwrap_or("");
            if token.is_empty() {
                return Err("bearer credential has no token".into());
            }
            Ok(AuthContext {
                headers: vec![("Authorization".into(), format!("Bearer {token}"))],
                cookies: None,
            })
        }
        "header" => {
            let name = cred.config["header_name"].as_str().unwrap_or("").trim();
            let value = cred.secret["header_value"].as_str().unwrap_or("");
            if name.is_empty() {
                return Err("header credential has no header_name".into());
            }
            Ok(AuthContext {
                headers: vec![(name.to_string(), value.to_string())],
                cookies: None,
            })
        }
        "cookie" => {
            let cookie = cred.secret["cookie"].as_str().unwrap_or("");
            if cookie.is_empty() {
                return Err("cookie credential has no cookie".into());
            }
            Ok(AuthContext {
                headers: vec![],
                cookies: Some(cookie.to_string()),
            })
        }
        "basic" => {
            let user = cred.secret["username"].as_str().unwrap_or("");
            let pass = cred.secret["password"].as_str().unwrap_or("");
            let enc = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
            Ok(AuthContext {
                headers: vec![("Authorization".into(), format!("Basic {enc}"))],
                cookies: None,
            })
        }
        "login_flow" => login_flow(http, cred).await,
        // Non-interactive OAuth2 grants (client_credentials / password) are a
        // direct token exchange, done node-side like login_flow. The redirect-based
        // authorization_code grant and interactive SSO need a browser, so they are
        // delegated to the control-plane broker (not yet wired here).
        "oauth2" => oauth2_token(http, cred).await,
        "sso" => Err(
            "sso session was not resolved by the auth broker (check AUTHBROKER_URL and the cf_authbroker logs)"
                .to_string(),
        ),
        other => Err(format!("unknown auth_type '{other}'")),
    }
}

/// Names commonly used for a per-session anti-CSRF form token.
const CSRF_FIELD_NAMES: [&str; 8] = [
    "csrf_token",
    "authenticity_token",
    "user_token",
    "_token",
    "__RequestVerificationToken",
    "csrfmiddlewaretoken",
    "_csrf",
    "csrf",
];

/// Pull a hidden form field's value out of an HTML page.
///
/// Handles both quoting styles and either attribute order, because real login
/// pages are written by hand and use all four combinations:
///   <input type="hidden" name="user_token" value="abc">
///   <input value='abc' name='user_token' />
fn extract_form_field(html: &str, field: &str) -> Option<String> {
    for quote in ['"', '\''] {
        let needle = format!("name={quote}{field}{quote}");
        // name=... then value=...
        if let Some(i) = html.find(&needle) {
            let rest = &html[i + needle.len()..];
            let stop = rest.find('>').unwrap_or(rest.len());
            if let Some(v) = attr_after(&rest[..stop], "value", quote) {
                return Some(v);
            }
        }
        // value=... then name=..., so look back to the start of the tag
        if let Some(i) = html.find(&needle) {
            let start = html[..i].rfind('<').unwrap_or(0);
            if let Some(v) = attr_after(&html[start..i], "value", quote) {
                return Some(v);
            }
        }
    }
    None
}

fn attr_after(fragment: &str, attr: &str, quote: char) -> Option<String> {
    let needle = format!("{attr}={quote}");
    let i = fragment.find(&needle)? + needle.len();
    let rest = &fragment[i..];
    let end = rest.find(quote)?;
    Some(rest[..end].to_string())
}

/// Replay a form/JSON login and capture the session as a cookie and/or bearer
/// token. Driven entirely by the credential's `config` (login_url, field names,
/// success check, token extraction).
async fn login_flow(
    http: &reqwest::Client,
    cred: &ResolvedCredential,
) -> Result<AuthContext, String> {
    let cfg = &cred.config;
    let login_url = cfg["login_url"].as_str().unwrap_or("").trim();
    if login_url.is_empty() {
        return Err("login_flow credential has no login_url".into());
    }
    let method = cfg["method"]
        .as_str()
        .unwrap_or("POST")
        .to_ascii_uppercase();
    let user_field = cfg["username_field"].as_str().unwrap_or("username");
    let pass_field = cfg["password_field"].as_str().unwrap_or("password");
    let username = cred.secret["username"].as_str().unwrap_or("");
    let password = cred.secret["password"].as_str().unwrap_or("");

    // A cookie store lets us capture Set-Cookie session cookies from the login,
    // and lets an anti-CSRF prefetch share the session the token was minted for.
    let jar = std::sync::Arc::new(reqwest::cookie::Jar::default());
    let client = reqwest::Client::builder()
        .cookie_provider(jar.clone())
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .unwrap_or_else(|_| http.clone());

    // Assemble the credential body plus any extra static fields.
    let mut form = serde_json::Map::new();
    form.insert(user_field.to_string(), json!(username));
    form.insert(pass_field.to_string(), json!(password));
    if let Some(extra) = cfg["extra_fields"].as_array() {
        for f in extra {
            if let (Some(n), Some(v)) = (f["name"].as_str(), f.get("value")) {
                form.insert(n.to_string(), v.clone());
            }
        }
    }

    // Anti-CSRF form token.
    //
    // Server-rendered login forms very commonly carry a hidden, per-session
    // token, and reject any POST without it. Static extra_fields cannot express
    // that: the token is minted for the session that fetched the page. So when
    // `csrf` is configured we GET the form first, on this same cookie jar, lift
    // the token out, and send it with the credentials.
    //
    // Config:
    //   "csrf": true                          fetch login_url, auto-detect the field
    //   "csrf": {"field": "user_token"}       name the field explicitly
    //   "csrf": {"url": "...", "field": ...}  fetch a different page for it
    //
    // Nothing here is app-specific: it is the mechanism every CSRF-protected
    // form login uses, and it fails closed by leaving the token out.
    let csrf_cfg = cfg.get("csrf");
    let csrf_enabled =
        matches!(csrf_cfg, Some(Value::Bool(true))) || matches!(csrf_cfg, Some(Value::Object(_)));
    if csrf_enabled {
        let form_url = csrf_cfg
            .and_then(|c| c.get("url"))
            .and_then(|v| v.as_str())
            .unwrap_or(login_url);
        let named = csrf_cfg
            .and_then(|c| c.get("field"))
            .and_then(|v| v.as_str());
        if let Ok(r) = client.get(form_url).send().await {
            let page = r.text().await.unwrap_or_default();
            let candidates: Vec<&str> = match named {
                Some(f) => vec![f],
                None => CSRF_FIELD_NAMES.to_vec(),
            };
            for field in candidates {
                if let Some(tok) = extract_form_field(&page, field) {
                    form.insert(field.to_string(), json!(tok));
                    break;
                }
            }
        }
    }

    let as_json = cfg["content_type"]
        .as_str()
        .map(|c| c.contains("json"))
        .unwrap_or(false)
        || cfg["as_json"].as_bool().unwrap_or(false);

    let mut rb = match method.as_str() {
        "GET" => client.get(login_url),
        "PUT" => client.put(login_url),
        _ => client.post(login_url),
    };
    rb = if as_json {
        rb.json(&Value::Object(form.clone()))
    } else {
        // application/x-www-form-urlencoded body, encoded by hand (reqwest's
        // .form() helper is not enabled in this build).
        let body = form
            .iter()
            .map(|(k, v)| {
                let val = v
                    .as_str()
                    .map(String::from)
                    .unwrap_or_else(|| v.to_string());
                format!("{}={}", form_urlencode(k), form_urlencode(&val))
            })
            .collect::<Vec<_>>()
            .join("&");
        rb.header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(body)
    };

    let resp = rb
        .send()
        .await
        .map_err(|e| format!("login request failed: {e}"))?;
    let status = resp.status();
    let resp_headers = resp.headers().clone();
    let final_url = resp.url().clone();
    let body_text = resp.text().await.unwrap_or_default();

    // Success check.
    let ok = match cfg["success_check"]["type"].as_str().unwrap_or("status") {
        "body_contains" => {
            let needle = cfg["success_check"]["value"].as_str().unwrap_or("");
            !needle.is_empty() && body_text.contains(needle)
        }
        "redirect" => {
            let want = cfg["success_check"]["value"].as_str().unwrap_or("");
            want.is_empty() || final_url.as_str().contains(want)
        }
        // default: 2xx/3xx status
        _ => status.is_success() || status.is_redirection(),
    };
    if !ok {
        return Err(format!(
            "login did not succeed (status {})",
            status.as_u16()
        ));
    }

    // Token extraction (optional). Otherwise rely on captured cookies.
    let mut headers: Vec<(String, String)> = Vec::new();
    if let Some(from) = cfg["token_extract"]["from"].as_str() {
        let reff = cfg["token_extract"]["ref"].as_str().unwrap_or("");
        let token = match from {
            "json" => extract_json_path(&body_text, reff),
            "header" => resp_headers
                .get(reff)
                .and_then(|v| v.to_str().ok())
                .map(String::from),
            "cookie" => cookie_value(&resp_headers, reff),
            _ => None,
        };
        if let Some(tok) = token.filter(|t| !t.is_empty()) {
            let header_name = cfg["token_extract"]["header"]
                .as_str()
                .unwrap_or("Authorization");
            let scheme = cfg["token_extract"]["scheme"].as_str().unwrap_or("Bearer");
            let value = if scheme.is_empty() {
                tok
            } else {
                format!("{scheme} {tok}")
            };
            headers.push((header_name.to_string(), value));
        }
    }

    // Captured cookies for the login host.
    let cookies = jar_cookie_header(&jar, &final_url);

    let ctx = AuthContext {
        headers,
        cookies: cookies.filter(|c| !c.is_empty()),
    };
    if ctx.is_empty() {
        return Err("login succeeded but produced no session token or cookie".into());
    }
    Ok(ctx)
}

/// Non-interactive OAuth2 token exchange (client_credentials / password grants).
/// Returns a Bearer AuthContext. authorization_code is deferred to the broker.
async fn oauth2_token(
    http: &reqwest::Client,
    cred: &ResolvedCredential,
) -> Result<AuthContext, String> {
    let cfg = &cred.config;
    let grant = cfg["grant_type"].as_str().unwrap_or("client_credentials");
    let token_url = cfg["token_url"].as_str().unwrap_or("").trim();
    if token_url.is_empty() {
        return Err("oauth2 credential has no token_url".into());
    }
    if grant == "authorization_code" {
        return Err("oauth2 authorization_code was not resolved by the auth broker (check AUTHBROKER_URL and the cf_authbroker logs)".into());
    }

    let client_id = cfg["client_id"].as_str().unwrap_or("");
    let scopes = match &cfg["scopes"] {
        Value::String(s) => s.clone(),
        Value::Array(a) => a
            .iter()
            .filter_map(|v| v.as_str())
            .collect::<Vec<_>>()
            .join(" "),
        _ => String::new(),
    };
    let audience = cfg["audience"].as_str().unwrap_or("");
    let client_secret = cred.secret["client_secret"].as_str().unwrap_or("");

    let mut form: Vec<(String, String)> = vec![("grant_type".into(), grant.to_string())];
    if !client_id.is_empty() {
        form.push(("client_id".into(), client_id.to_string()));
    }
    if !client_secret.is_empty() {
        form.push(("client_secret".into(), client_secret.to_string()));
    }
    if !scopes.is_empty() {
        form.push(("scope".into(), scopes));
    }
    if !audience.is_empty() {
        form.push(("audience".into(), audience.to_string()));
    }
    if grant == "password" {
        let u = cred.secret["username"].as_str().unwrap_or("");
        let p = cred.secret["password"].as_str().unwrap_or("");
        form.push(("username".into(), u.to_string()));
        form.push(("password".into(), p.to_string()));
    }

    let body = form
        .iter()
        .map(|(k, v)| format!("{}={}", form_urlencode(k), form_urlencode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let resp = http
        .post(token_url)
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .header(reqwest::header::ACCEPT, "application/json")
        .body(body)
        .send()
        .await
        .map_err(|e| format!("token request failed: {e}"))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        let snippet: String = text.chars().take(200).collect();
        return Err(format!(
            "token endpoint returned {} ({snippet})",
            status.as_u16()
        ));
    }
    let token = extract_json_path(&text, "access_token")
        .ok_or_else(|| "token response had no access_token".to_string())?;
    let token_type = extract_json_path(&text, "token_type").unwrap_or_else(|| "Bearer".into());
    let scheme = if token_type.eq_ignore_ascii_case("bearer") {
        "Bearer".to_string()
    } else {
        token_type
    };
    Ok(AuthContext {
        headers: vec![("Authorization".into(), format!("{scheme} {token}"))],
        cookies: None,
    })
}

/// Resolve an identity matrix (each `{role, credential_id?}`) into the cortex
/// `identities` shape: `[{"role":.., "auth":{headers,cookies}}]`. An entry with
/// no `credential_id` is treated as the anonymous identity (empty auth). Entries
/// whose credential fails to resolve are skipped (logged) so a partial matrix
/// still runs.
pub async fn resolve_identities(
    http: &reqwest::Client,
    api_url: &str,
    node_api_key: &str,
    identities: &[Value],
    host: &str,
) -> Vec<Value> {
    let mut out = Vec::new();
    for ident in identities {
        let role = ident["role"].as_str().unwrap_or("").trim().to_string();
        if role.is_empty() {
            continue;
        }
        let cid = ident["credential_id"].as_str().filter(|s| !s.is_empty());
        let auth = match cid {
            Some(id) => match resolve_auth(http, api_url, node_api_key, id, host).await {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("[op] authz identity '{role}' resolve failed ({id}): {e}");
                    continue;
                }
            },
            None => json!({ "headers": {}, "cookies": "" }),
        };
        out.push(json!({ "role": role, "auth": auth }));
    }
    out
}

/// Resolve + build + cache in one call. Returns the `auth` JSON object to inject
/// into an engine request, or an error string (logged by the caller).
/// Resolve a credential into SEVERAL independent sessions.
///
/// One session is a bottleneck, not a convenience. PHP locks the session file
/// for the duration of each request, so every worker sharing one cookie is
/// serialised by the target: measured on Mutillidae, eight concurrent requests
/// on one session produce a perfect staircase while eight without a session run
/// flat. Add a time-based payload, which parks that lock for five or ten
/// seconds, and the rest of the pass queues behind it and times out. Those
/// timeouts are then reported as "the endpoint did not answer", so the symptom
/// is missing coverage rather than slowness.
///
/// Only a `login_flow` credential can be multiplied: logging in again is what
/// produces a genuinely separate session. A bearer token, an API key or a
/// browser-brokered SSO session is the same value however many times it is
/// asked for, so those return a single entry and the caller shares it - which
/// is correct, because a stateless credential has no lock to contend on.
///
/// Bounded deliberately. Every extra session is a real login against someone
/// else's application: it shows up in their audit log, it counts against
/// lockout thresholds, and on a target with per-account rate limiting it is
/// hostile. Four is enough to keep the workers busy and small enough to explain.
pub async fn resolve_auth_pool(
    http: &reqwest::Client,
    api_url: &str,
    node_api_key: &str,
    credential_id: &str,
    host: &str,
    want: usize,
) -> Result<Vec<Value>, String> {
    let first = resolve_auth(http, api_url, node_api_key, credential_id, host).await?;
    let want = want.clamp(1, 4);
    if want == 1 {
        return Ok(vec![first]);
    }
    let cred = resolve(http, api_url, node_api_key, credential_id, host).await?;
    // Anything that is not a form login hands back the same material each time.
    if cred.auth_type != "login_flow" || cred.resolved_auth.is_some() {
        return Ok(vec![first]);
    }
    let mut out = vec![first];
    for _ in 1..want {
        match build_context(http, &cred).await {
            Ok(ctx) => out.push(ctx.to_json()),
            // A login that fails the second time is not fatal: the pass runs on
            // the sessions it has. Silence would be, so it is reported.
            Err(e) => {
                eprintln!("[creds] extra session for {credential_id} failed: {e}");
                break;
            }
        }
    }
    Ok(out)
}

pub async fn resolve_auth(
    http: &reqwest::Client,
    api_url: &str,
    node_api_key: &str,
    credential_id: &str,
    host: &str,
) -> Result<Value, String> {
    if let Some(ctx) = cache_get(credential_id) {
        return Ok(ctx.to_json());
    }
    let cred = resolve(http, api_url, node_api_key, credential_id, host).await?;
    // Browser-brokered types (sso / oauth2 authcode) come back pre-resolved.
    let ctx = if let Some(ra) = &cred.resolved_auth {
        auth_context_from_json(ra)
    } else {
        build_context(http, &cred).await?
    };
    cache_put(credential_id, &ctx);
    Ok(ctx.to_json())
}

// --- helpers ---------------------------------------------------------------

/// Minimal application/x-www-form-urlencoded value encoder.
fn form_urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Very small JSON path getter supporting dotted paths like "data.token".
fn extract_json_path(body: &str, path: &str) -> Option<String> {
    let v: Value = serde_json::from_str(body).ok()?;
    let mut cur = &v;
    for seg in path.split('.').filter(|s| !s.is_empty()) {
        cur = cur.get(seg)?;
    }
    match cur {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Pull a named cookie's value out of Set-Cookie headers.
fn cookie_value(headers: &reqwest::header::HeaderMap, name: &str) -> Option<String> {
    for hv in headers.get_all(reqwest::header::SET_COOKIE).iter() {
        if let Ok(s) = hv.to_str()
            && let Some(rest) = s.strip_prefix(&format!("{name}="))
        {
            return Some(rest.split(';').next().unwrap_or("").to_string());
        }
    }
    None
}

/// The Cookie header value the jar would send to `url` (semicolon-joined).
fn jar_cookie_header(jar: &reqwest::cookie::Jar, url: &reqwest::Url) -> Option<String> {
    use reqwest::cookie::CookieStore;
    jar.cookies(url)
        .and_then(|hv| hv.to_str().ok().map(String::from))
}

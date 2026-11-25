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
//!   session token/cookie. On a node that sends through a proxy, the login goes
//!   through the op's lease on the egress gateway like the rest of the op.
//! - oauth2 / sso: delegated to the control-plane broker (not yet wired here).
//!
//! Built contexts are cached per credential id (with a short TTL) so we do not
//! re-login on every request. The control plane is still asked on every use,
//! since its host check is what decides whether the auth may go to that op's
//! target; the cache only saves rebuilding the session.

use base64::Engine as _;
use serde_json::{Value, json};

use crate::api::SendApi;
use crate::egress::gateway::Lease;
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

/// Request auth for one credential, with the hosts the credential is for.
#[derive(Clone, Debug)]
pub struct ScopedAuth {
    /// The `auth` object the engines consume.
    pub auth: Value,
    /// The credential's `scope_hosts` as the platform holds them. Empty when it
    /// records none, which the platform reads as no restriction.
    pub hosts: Vec<String>,
}

// Session cache: credential_id -> (context, the credential it was built from,
// built_at). Login/OAuth results are reused for CACHE_TTL. It holds no scope
// decision: a hit is used only after the control plane has resolved the
// credential for the op's own host.
type CacheEntry = (AuthContext, u64, Instant);
static CACHE: Mutex<Option<HashMap<String, CacheEntry>>> = Mutex::new(None);
const CACHE_TTL: Duration = Duration::from_secs(600);

/// What a built context depends on, so an edited credential is built again.
fn material(cred: &ResolvedCredential) -> u64 {
    use std::hash::{DefaultHasher, Hash, Hasher};
    let mut h = DefaultHasher::new();
    cred.auth_type.hash(&mut h);
    cred.config.to_string().hash(&mut h);
    cred.secret.to_string().hash(&mut h);
    h.finish()
}

fn cache_get(id: &str, material: u64) -> Option<AuthContext> {
    let guard = CACHE.lock().ok()?;
    let map = guard.as_ref()?;
    let (ctx, built_from, at) = map.get(id)?;
    if *built_from == material && at.elapsed() < CACHE_TTL {
        Some(ctx.clone())
    } else {
        None
    }
}

fn cache_put(id: &str, material: u64, ctx: &AuthContext) {
    if let Ok(mut guard) = CACHE.lock() {
        let map = guard.get_or_insert_with(HashMap::new);
        map.insert(id.to_string(), (ctx.clone(), material, Instant::now()));
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
        .send_api()
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

/// The client a login or token exchange reaches the target with, through `egress`
/// when the op has one. Never the control-plane client in that case: a login is
/// target traffic, and a proxied node sends none of that from its own address.
fn target_client(
    builder: reqwest::ClientBuilder,
    egress: &Lease,
) -> Result<reqwest::Client, String> {
    let proxy = reqwest::Proxy::all(egress.proxy_url())
        .map_err(|_| "the egress gateway's address could not be used".to_string())?;
    builder
        .proxy(proxy)
        .build()
        .map_err(|e| format!("the login client could not be built: {e}"))
}

/// The redirect policy for a login or token request, whose body carries the
/// secret. A redirect that leaves the origin of the first request is followed
/// only when the client sends it without the body: a 303, or a 301 or 302
/// answering a POST. A 307 or 308, or a 301 or 302 answering any other method,
/// would send the body on unchanged, so it comes back as the 3xx it is.
fn secret_body_redirects(method: &str) -> reqwest::redirect::Policy {
    use reqwest::StatusCode;
    let post = method.eq_ignore_ascii_case("POST");
    let limit = reqwest::redirect::Policy::limited(5);
    reqwest::redirect::Policy::custom(move |attempt| {
        let body_dropped = attempt.status() == StatusCode::SEE_OTHER
            || (post
                && matches!(
                    attempt.status(),
                    StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND
                ));
        let stays = attempt
            .previous()
            .first()
            .is_some_and(|from| keeps_origin(from, attempt.url()));
        if stays || body_dropped {
            limit.redirect(attempt)
        } else {
            attempt.stop()
        }
    })
}

/// The same host on the same scheme and port, or the same host moved from `http`
/// to `https` with both on their default ports.
fn keeps_origin(from: &reqwest::Url, to: &reqwest::Url) -> bool {
    if from.host_str() != to.host_str() {
        return false;
    }
    if from.scheme() == to.scheme() {
        return from.port_or_known_default() == to.port_or_known_default();
    }
    from.scheme() == "http"
        && to.scheme() == "https"
        && from.port().is_none()
        && to.port().is_none()
}

/// Build a concrete AuthContext from a resolved credential. Executes a login for
/// login_flow types; static types are built directly. `egress` is the op's lease when
/// this node sends through a proxy; a login then goes through it.
pub async fn build_context(
    http: &reqwest::Client,
    cred: &ResolvedCredential,
    egress: Option<&Lease>,
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
        "login_flow" => login_flow(cred, egress).await,
        // Non-interactive OAuth2 grants (client_credentials / password) are a
        // direct token exchange, done node-side like login_flow. The redirect-based
        // authorization_code grant and interactive SSO need a browser, so they are
        // delegated to the control-plane broker (not yet wired here).
        "oauth2" => oauth2_token(http, cred, egress).await,
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
    cred: &ResolvedCredential,
    egress: Option<&Lease>,
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
    let builder = reqwest::Client::builder()
        .cookie_provider(jar.clone())
        .timeout(Duration::from_secs(20))
        .redirect(secret_body_redirects(&method));
    let client = match egress {
        Some(lease) => target_client(builder, lease)?,
        // Never the node's shared client in its place: that client follows any
        // redirect, and this request carries the password.
        None => builder
            .build()
            .map_err(|e| format!("the login client could not be built: {e}"))?,
    };

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

    // Captured cookies for the login host: where the login ended when that is still
    // the login host, and the login URL itself when a redirect took it elsewhere. The
    // other host's cookies are not this credential's session, and they would go to the
    // target with every request.
    let login = reqwest::Url::parse(login_url).map_err(|e| format!("login_url: {e}"))?;
    let cookie_url = if keeps_origin(&login, &final_url) {
        &final_url
    } else {
        &login
    };
    let cookies = jar_cookie_header(&jar, cookie_url);

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
    // Kept for the shape every builder shares. The token request has a client of
    // its own, for its redirect policy.
    _http: &reqwest::Client,
    cred: &ResolvedCredential,
    egress: Option<&Lease>,
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
    let builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .redirect(secret_body_redirects("POST"));
    let client = match egress {
        Some(lease) => target_client(builder, lease)?,
        None => builder
            .build()
            .map_err(|e| format!("the token client could not be built: {e}"))?,
    };
    let resp = client
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

/// Resolve an identity matrix (each `{role, credential_id?}`) into the plessor
/// `identities` shape: `[{"role":.., "auth":{headers,cookies}}]`. An entry with
/// no `credential_id` is treated as the anonymous identity (empty auth). Entries
/// whose credential fails to resolve are skipped (logged) so a partial matrix
/// still runs.
///
/// Also returns the hosts of each credential that resolved, since every identity's
/// auth goes to every endpoint of the pass.
pub async fn resolve_identities(
    http: &reqwest::Client,
    api_url: &str,
    node_api_key: &str,
    identities: &[Value],
    host: &str,
    egress: Option<&Lease>,
) -> (Vec<Value>, Vec<Vec<String>>) {
    let mut out = Vec::new();
    let mut scopes = Vec::new();
    for ident in identities {
        let role = ident["role"].as_str().unwrap_or("").trim().to_string();
        if role.is_empty() {
            continue;
        }
        let cid = ident["credential_id"].as_str().filter(|s| !s.is_empty());
        let auth = match cid {
            Some(id) => {
                match resolve_auth_scoped(http, api_url, node_api_key, id, host, egress).await {
                    Ok(a) => {
                        scopes.push(a.hosts);
                        a.auth
                    }
                    Err(e) => {
                        eprintln!("[op] authz identity '{role}' resolve failed ({id}): {e}");
                        continue;
                    }
                }
            }
            None => json!({ "headers": {}, "cookies": "" }),
        };
        out.push(json!({ "role": role, "auth": auth }));
    }
    (out, scopes)
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
    egress: Option<&Lease>,
) -> Result<(Vec<Value>, Vec<String>), String> {
    let first =
        resolve_auth_scoped(http, api_url, node_api_key, credential_id, host, egress).await?;
    let hosts = first.hosts;
    let first = first.auth;
    let want = want.clamp(1, 4);
    if want == 1 {
        return Ok((vec![first], hosts));
    }
    let cred = resolve(http, api_url, node_api_key, credential_id, host).await?;
    // Anything that is not a form login hands back the same material each time.
    if cred.auth_type != "login_flow" || cred.resolved_auth.is_some() {
        return Ok((vec![first], hosts));
    }
    let mut out = vec![first];
    for _ in 1..want {
        match build_context(http, &cred, egress).await {
            Ok(ctx) => out.push(ctx.to_json()),
            // A login that fails the second time is not fatal: the pass runs on
            // the sessions it has. Silence would be, so it is reported.
            Err(e) => {
                eprintln!("[creds] extra session for {credential_id} failed: {e}");
                break;
            }
        }
    }
    Ok((out, hosts))
}

pub async fn resolve_auth(
    http: &reqwest::Client,
    api_url: &str,
    node_api_key: &str,
    credential_id: &str,
    host: &str,
    egress: Option<&Lease>,
) -> Result<Value, String> {
    resolve_auth_scoped(http, api_url, node_api_key, credential_id, host, egress)
        .await
        .map(|a| a.auth)
}

/// [`resolve_auth`], with the hosts the credential is for. An op whose engine may
/// reach hosts besides `host` keeps the credential to these.
pub async fn resolve_auth_scoped(
    http: &reqwest::Client,
    api_url: &str,
    node_api_key: &str,
    credential_id: &str,
    host: &str,
    egress: Option<&Lease>,
) -> Result<ScopedAuth, String> {
    // Asked on every use, cache or not: the control plane decides whether this
    // credential may be sent to `host`, and a session cached for one host says
    // nothing about another.
    let cred = resolve(http, api_url, node_api_key, credential_id, host).await?;
    // Browser-brokered types (sso / oauth2 authcode) come back pre-resolved.
    let ctx = if let Some(ra) = &cred.resolved_auth {
        auth_context_from_json(ra)
    } else {
        let built_from = material(&cred);
        match cache_get(credential_id, built_from) {
            Some(ctx) => ctx,
            None => {
                let ctx = build_context(http, &cred, egress).await?;
                cache_put(credential_id, built_from, &ctx);
                ctx
            }
        }
    };
    Ok(ScopedAuth {
        auth: ctx.to_json(),
        hosts: cred.scope_hosts,
    })
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

#[cfg(test)]
mod redirect_tests {
    //! A login or token request carries the secret in its body, and the client
    //! sends that body on through a 307 or 308. Such a redirect to another host
    //! must come back unfollowed.
    use super::*;
    use std::io::{Read, Write};
    use std::sync::Arc;

    pub(super) type Seen = Arc<Mutex<Vec<String>>>;

    /// A loopback listener that keeps each request (head and body) it reads and
    /// answers it with `reply(path)`.
    fn listener(ip: &str, reply: impl Fn(&str) -> String + Send + 'static) -> (u16, Seen) {
        listener_with(ip, move |req| {
            reply(req.split_whitespace().nth(1).unwrap_or("/"))
        })
    }

    /// [`listener`], answering each request with `reply(whole request)`.
    pub(super) fn listener_with(
        ip: &str,
        reply: impl Fn(&str) -> String + Send + 'static,
    ) -> (u16, Seen) {
        let l = std::net::TcpListener::bind((ip, 0)).unwrap();
        let port = l.local_addr().unwrap().port();
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { return };
                let _ = s.set_read_timeout(Some(Duration::from_millis(300)));
                let mut req = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    if let Some(end) = req.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&req[..end]).to_ascii_lowercase();
                        let len = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if req.len() >= end + 4 + len {
                            break;
                        }
                    }
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => req.extend_from_slice(&buf[..n]),
                    }
                }
                let req = String::from_utf8_lossy(&req).to_string();
                let answer = reply(&req);
                log.lock().unwrap().push(req);
                let _ = s.write_all(answer.as_bytes());
            }
        });
        (port, seen)
    }

    fn redirect(status: &str, location: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\nLocation: {location}\r\nSet-Cookie: sid=on-login-host; Path=/\r\n\
             Content-Length: 0\r\nConnection: close\r\n\r\n"
        )
    }

    fn other_host() -> (u16, Seen) {
        listener("127.0.0.2", |_| {
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_string()
        })
    }

    fn cred(auth_type: &str, config: Value, secret: Value) -> ResolvedCredential {
        ResolvedCredential {
            name: "test".into(),
            auth_type: auth_type.into(),
            config,
            secret,
            scope_hosts: Vec::new(),
            resolved_auth: None,
        }
    }

    fn assert_secret_stayed(seen: &Seen, secret: &str) {
        let seen = seen.lock().unwrap();
        assert!(
            !seen.iter().any(|r| r.contains(secret)),
            "the other host was sent the secret: {seen:?}"
        );
    }

    #[tokio::test]
    async fn a_login_body_is_not_sent_on_to_another_host() {
        for status in ["307 Temporary Redirect", "308 Permanent Redirect"] {
            for method in ["POST", "PUT", "GET"] {
                let (b, b_seen) = other_host();
                let to = format!("http://127.0.0.2:{b}/collect");
                let (a, _) = listener("127.0.0.1", move |_| redirect(status, &to));
                let c = cred(
                    "login_flow",
                    json!({"login_url": format!("http://127.0.0.1:{a}/login"), "method": method}),
                    json!({"username": "alice", "password": "saved-password"}),
                );
                let _ = login_flow(&c, None).await;
                assert_secret_stayed(&b_seen, "saved-password");
            }
        }
        // A 301 or 302 keeps the body of anything but a POST.
        for method in ["PUT", "GET"] {
            let (b, b_seen) = other_host();
            let to = format!("http://127.0.0.2:{b}/collect");
            let (a, _) = listener("127.0.0.1", move |_| redirect("302 Found", &to));
            let c = cred(
                "login_flow",
                json!({"login_url": format!("http://127.0.0.1:{a}/login"), "method": method}),
                json!({"username": "alice", "password": "saved-password"}),
            );
            let _ = login_flow(&c, None).await;
            assert_secret_stayed(&b_seen, "saved-password");
        }
    }

    #[tokio::test]
    async fn a_login_still_follows_a_redirect_that_drops_the_body() {
        let (b, b_seen) = other_host();
        let to = format!("http://127.0.0.2:{b}/home");
        let (a, _) = listener("127.0.0.1", move |_| redirect("303 See Other", &to));
        let c = cred(
            "login_flow",
            json!({"login_url": format!("http://127.0.0.1:{a}/login")}),
            json!({"username": "alice", "password": "saved-password"}),
        );
        let _ = login_flow(&c, None).await;
        let seen = b_seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "the 303 was not followed");
        assert!(seen[0].starts_with("GET /home "), "{}", seen[0]);
        assert!(!seen[0].contains("saved-password"), "{}", seen[0]);
    }

    /// The session is the login host's. A login that ends on another host, as one sent
    /// on to a landing page elsewhere does, keeps the cookies the login host set and
    /// takes none from the other host.
    #[tokio::test]
    async fn a_login_keeps_the_login_host_s_cookies_after_a_redirect_away() {
        let (b, b_seen) = listener("127.0.0.2", |_| {
            "HTTP/1.1 200 OK\r\nSet-Cookie: elsewhere=from-other-host; Path=/\r\n\
             Content-Length: 2\r\nConnection: close\r\n\r\nok"
                .to_string()
        });
        let to = format!("http://127.0.0.2:{b}/home");
        let (a, _) = listener("127.0.0.1", move |_| redirect("302 Found", &to));
        let c = cred(
            "login_flow",
            json!({"login_url": format!("http://127.0.0.1:{a}/login")}),
            json!({"username": "alice", "password": "saved-password"}),
        );
        let ctx = login_flow(&c, None).await.unwrap();
        assert_eq!(b_seen.lock().unwrap().len(), 1, "the 302 was not followed");
        assert_eq!(ctx.cookies.as_deref(), Some("sid=on-login-host"));
    }

    #[tokio::test]
    async fn a_token_request_is_not_sent_on_to_another_host() {
        for status in ["307 Temporary Redirect", "308 Permanent Redirect"] {
            let (b, b_seen) = other_host();
            let to = format!("http://127.0.0.2:{b}/token");
            let (a, _) = listener("127.0.0.1", move |_| redirect(status, &to));
            let c = cred(
                "oauth2",
                json!({"token_url": format!("http://127.0.0.1:{a}/token"), "client_id": "app"}),
                json!({"client_secret": "saved-client-secret"}),
            );
            let _ = oauth2_token(&reqwest::Client::new(), &c, None).await;
            assert_secret_stayed(&b_seen, "saved-client-secret");
        }
    }
}

#[cfg(test)]
mod cache_tests {
    //! A session built for one op is reused by the next, but the platform still
    //! decides for every op whether the credential may go to that op's host.
    use super::redirect_tests::{Seen, listener_with};
    use super::*;

    fn reply_json(body: &Value) -> String {
        let body = body.to_string();
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{body}",
            body.len()
        )
    }

    /// A control plane that resolves `data` for a request naming `allowed` as
    /// the host and refuses any other host, as /api/v1/creds/resolve does.
    fn control_plane(allowed: &'static str, data: Arc<Mutex<Value>>) -> (String, Seen) {
        let (port, seen) = listener_with("127.0.0.1", move |req| {
            let body = req.split("\r\n\r\n").nth(1).unwrap_or("");
            let asked: Value = serde_json::from_str(body).unwrap_or(Value::Null);
            if asked["host"].as_str() == Some(allowed) {
                reply_json(&json!({"status": 200, "data": data.lock().unwrap().clone()}))
            } else {
                reply_json(&json!({
                    "status": 403,
                    "message": "Credential is not in scope for this host",
                }))
            }
        });
        (format!("http://127.0.0.1:{port}"), seen)
    }

    use std::sync::Arc;

    #[tokio::test]
    async fn a_cached_credential_is_still_checked_against_the_new_host() {
        let data = Arc::new(Mutex::new(json!({
            "name": "api token",
            "auth_type": "bearer",
            "config": {},
            "secret": {"token": "saved-token"},
            "scope_hosts": ["app.victim.example"],
        })));
        let (api, _) = control_plane("app.victim.example", data);
        let http = reqwest::Client::new();
        let id = "cache-test-host-check";
        let ok = resolve_auth(&http, &api, "key", id, "app.victim.example", None).await;
        assert!(ok.is_ok(), "{ok:?}");
        let other = resolve_auth(&http, &api, "key", id, "attacker.example", None).await;
        assert!(
            other.is_err(),
            "the credential was handed out for a host the platform refuses: {other:?}"
        );
        let other = resolve_auth_scoped(&http, &api, "key", id, "attacker.example", None).await;
        assert!(other.is_err(), "{other:?}");
        let (ids, _) = resolve_identities(
            &http,
            &api,
            "key",
            &[json!({"role": "user", "credential_id": id})],
            "attacker.example",
            None,
        )
        .await;
        assert!(ids.is_empty(), "{ids:?}");
        let pool = resolve_auth_pool(&http, &api, "key", id, "attacker.example", 1, None).await;
        assert!(pool.is_err(), "{pool:?}");
    }

    /// A login server that counts logins and hands out a numbered session.
    fn login_server() -> (String, Seen) {
        let n = Arc::new(Mutex::new(0u32));
        let (port, seen) = listener_with("127.0.0.1", move |_| {
            let mut n = n.lock().unwrap();
            *n += 1;
            format!(
                "HTTP/1.1 200 OK\r\nSet-Cookie: sid=session-{n}; Path=/\r\n\
                 Content-Length: 2\r\nConnection: close\r\n\r\nok"
            )
        });
        (format!("http://127.0.0.1:{port}/login"), seen)
    }

    #[tokio::test]
    async fn a_login_session_is_reused_while_the_credential_is_unchanged() {
        let (login_url, logins) = login_server();
        let data = Arc::new(Mutex::new(json!({
            "name": "form login",
            "auth_type": "login_flow",
            "config": {"login_url": login_url},
            "secret": {"username": "alice", "password": "first-password"},
            "scope_hosts": ["app.victim.example"],
        })));
        let (api, asks) = control_plane("app.victim.example", Arc::clone(&data));
        let http = reqwest::Client::new();
        let id = "cache-test-login-reuse";
        let a = resolve_auth(&http, &api, "key", id, "app.victim.example", None).await;
        let b = resolve_auth(&http, &api, "key", id, "app.victim.example", None).await;
        assert!(a.is_ok() && b.is_ok(), "{a:?} {b:?}");
        assert_eq!(a, b);
        assert_eq!(logins.lock().unwrap().len(), 1, "the login was repeated");
        assert_eq!(asks.lock().unwrap().len(), 2, "the platform was not asked");

        // The credential is edited on the platform: the old session is not used.
        data.lock().unwrap()["secret"]["password"] = json!("second-password");
        let c = resolve_auth(&http, &api, "key", id, "app.victim.example", None).await;
        assert!(c.is_ok(), "{c:?}");
        assert_ne!(a, c, "a session from the old credential was reused");
        let logins = logins.lock().unwrap();
        assert_eq!(logins.len(), 2);
        assert!(logins[1].contains("second-password"), "{}", logins[1]);
    }
}

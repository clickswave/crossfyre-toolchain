//! A minimal, nuclei-compatible template executor (the template-compat mode).
//!
//! It parses a practical subset of the nuclei YAML schema (http protocol: method,
//! path with `{{BaseURL}}`, and `word`/`status`/`regex`/`size` matchers with
//! `matchers-condition`) and runs it against a target. Every match is confirmed by
//! re-issuing the request (the correctness pipeline's REPRODUCE step) before it is
//! returned, so transient responses do not become findings. A fuller DSL/OAST
//! implementation is the documented next step (docs/tier1-engines-plan.md s6).

use regex::Regex;
use serde::Deserialize;
use std::sync::LazyLock;
use transport::Client;

#[derive(Debug, Deserialize)]
pub struct Template {
    pub id: String,
    #[serde(default)]
    pub info: Info,
    #[serde(default, alias = "requests")]
    pub http: Vec<HttpReq>,
}

#[derive(Debug, Deserialize, Default)]
pub struct Info {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Deserialize)]
pub struct HttpReq {
    #[serde(default = "default_method")]
    pub method: String,
    #[serde(default)]
    pub path: Vec<String>,
    #[serde(default)]
    pub matchers: Vec<Matcher>,
    #[serde(default = "default_and", rename = "matchers-condition")]
    pub matchers_condition: String,
    /// Named payload lists substituted into `{{name}}` placeholders in the path
    /// (active fuzzing: LFI, traversal, injection wordlists, ...). We generate a
    /// capped cartesian product across referenced lists.
    #[serde(default)]
    pub payloads: std::collections::HashMap<String, Vec<String>>,
    /// nuclei attack mode (informational here; we always do a capped cartesian).
    #[serde(default)]
    // populated but not read yet; kept so the struct still mirrors its config
    #[allow(dead_code)]
    pub attack: String,
    /// Request headers (name -> value). Payload/OOB placeholders in values are
    /// substituted like the path, so header-based checks (a forged Authorization,
    /// a Content-Type for a body) are expressible.
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
    /// Optional request body for POST/PUT/PATCH. Supports `{{payload}}` and OOB
    /// placeholder substitution, so JSON/XML/form injection checks work.
    #[serde(default)]
    pub body: Option<String>,
    /// Send the request-target verbatim over a raw socket instead of through
    /// reqwest, so `.`/`%2e` dot-segments are NOT normalised away client-side.
    /// Required for path-traversal probes whose bypass depends on the server
    /// doing the normalisation (e.g. CVE-2021-41773). nuclei's `unsafe`.
    #[serde(default, rename = "unsafe")]
    pub unsafe_raw: bool,
}

/// Max concrete requests generated from one path's payload expansion (safety cap
/// consistent with the distribution rate/fanout limits).
const MAX_PAYLOAD_REQUESTS: usize = 256;

/// Cap on WAF-evasion encodings tried per blocked request. Only reached under
/// evasive posture and only when the original request looked WAF-blocked, so it
/// does not multiply request volume on unprotected targets.
const MAX_EVASION_VARIANTS: usize = 8;

#[derive(Debug, Deserialize)]
pub struct Matcher {
    #[serde(rename = "type")]
    pub mtype: String,
    #[serde(default)]
    pub part: String,
    #[serde(default)]
    pub words: Vec<String>,
    #[serde(default)]
    pub regex: Vec<String>,
    #[serde(default)]
    pub status: Vec<u16>,
    #[serde(default)]
    pub size: Vec<usize>,
    /// nuclei-style dsl expressions (e.g. "status_code==200 && contains(body,'x')").
    #[serde(default)]
    pub dsl: Vec<String>,
    #[serde(default = "default_or")]
    pub condition: String,
    #[serde(default)]
    pub negative: bool,
}

fn default_method() -> String {
    "GET".to_string()
}
fn default_and() -> String {
    "and".to_string()
}
fn default_or() -> String {
    "or".to_string()
}

/// A confirmed template match.
pub struct Match {
    pub template_id: String,
    pub name: String,
    pub severity: String,
    pub description: String,
    pub matched_at: String,
}

struct Resp {
    status: u16,
    headers: String,
    body: String,
    /// The URL this response came from. Needed so a matcher can tell evidence
    /// from an echo: see `matches_one`.
    url: String,
}

const OOB_MARKERS: [&str; 2] = ["{{interactsh-url}}", "{{oast-url}}"];

fn references_oob(req: &HttpReq) -> bool {
    let in_str = |s: &str| OOB_MARKERS.iter().any(|m| s.contains(m));
    req.path.iter().any(|p| in_str(p))
        || req.payloads.values().flatten().any(|v| in_str(v))
        || req.body.as_deref().map(in_str).unwrap_or(false)
        || req.headers.values().any(|v| in_str(v))
}

/// Execute a template against `base` (e.g. "https://example.com"), returning
/// confirmed matches. Response-based matchers are re-requested once (reproduce);
/// out-of-band (interactsh) requests are confirmed by an actual OAST callback.
pub async fn eval_template(
    client: &Client,
    base: &str,
    tmpl: &Template,
    oast: Option<&crate::oast::OastClient>,
    evasive: bool,
) -> Vec<Match> {
    let mut out = Vec::new();
    for req in &tmpl.http {
        let method = req.method.to_uppercase();

        // Out-of-band request: only runnable when an OAST server is configured.
        if references_oob(req) {
            let Some(oc) = oast else { continue };
            // Register a fresh correlation (sealed to this scan's keypair) for this
            // template, so callbacks are attributable and encrypted end to end.
            let Some(reg) = oc.register(client).await else {
                continue;
            };
            let host = oc.host(&reg);
            let mut fired = false;
            for raw_path in &req.path {
                for mut v in expand_request(req, raw_path, base, MAX_PAYLOAD_REQUESTS) {
                    apply_oob(&mut v, &host);
                    let _ = fetch(client, &method, &v).await;
                    fired = true;
                }
            }
            if !fired {
                oc.deregister(client, &reg).await;
                continue;
            }
            // Poll for the callback: the target processes the payload asynchronously.
            let mut hits = 0u64;
            for _ in 0..4 {
                tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
                hits = oc.poll(client, &reg).await;
                if hits > 0 {
                    break;
                }
            }
            oc.deregister(client, &reg).await;
            if hits > 0 {
                let base_desc = if tmpl.info.description.is_empty() {
                    tmpl.id.clone()
                } else {
                    tmpl.info.description.clone()
                };
                out.push(Match {
                    template_id: tmpl.id.clone(),
                    name: if tmpl.info.name.is_empty() {
                        tmpl.id.clone()
                    } else {
                        tmpl.info.name.clone()
                    },
                    severity: if tmpl.info.severity.is_empty() {
                        "high".to_string()
                    } else {
                        tmpl.info.severity.clone()
                    },
                    description: format!(
                        "{base_desc} Confirmed out-of-band: {hits} callback(s) to {host}."
                    ),
                    matched_at: base.to_string(),
                });
            }
            continue;
        }

        // Response-based request.
        for raw_path in &req.path {
            for v in expand_request(req, raw_path, base, MAX_PAYLOAD_REQUESTS) {
                // GENERATE + DETECT: issue the request. `unsafe` templates go over
                // the raw sender (verbatim request-target); everything else via
                // reqwest.
                let r1 = match send_variant(client, &method, req.unsafe_raw, &v).await {
                    Some(r) => r,
                    None => continue,
                };

                // Pick the request that reproduces the finding. Normally that is
                // `v` itself. Under evasive posture, if `v` was WAF-blocked rather
                // than answered by the app, retry payload-encoding variants until
                // one clears the WAF and still matches - so a signature WAF cannot
                // mask the bug. `unsafe` (raw) templates are left to the raw-path
                // track; their evasion is byte-level, not payload-level.
                let (winner, evaded) = if matches_all(req, &r1) {
                    (v.clone(), false)
                } else if evasive && !req.unsafe_raw && resp_is_blocked(&r1) {
                    let mut chosen: Option<ReqVariant> = None;
                    for (mu, mb) in
                        adaptive::evasion::variants(&v.url, v.body.as_deref(), MAX_EVASION_VARIANTS)
                    {
                        let vv = ReqVariant {
                            url: mu,
                            headers: v.headers.clone(),
                            body: mb,
                        };
                        if let Some(rr) = fetch(client, &method, &vv).await
                            && matches_all(req, &rr)
                        {
                            chosen = Some(vv);
                            break;
                        }
                    }
                    match chosen {
                        Some(vv) => (vv, true),
                        None => continue,
                    }
                } else {
                    continue;
                };

                // CONFIRM: re-issue the winning variant once; must match again.
                let r2 = match send_variant(client, &method, req.unsafe_raw, &winner).await {
                    Some(r) => r,
                    None => continue,
                };
                if !matches_all(req, &r2) {
                    continue;
                }

                let mut description = tmpl.info.description.clone();
                if evaded {
                    description.push_str(" (confirmed via WAF-evasion payload encoding)");
                }
                out.push(Match {
                    template_id: tmpl.id.clone(),
                    name: if tmpl.info.name.is_empty() {
                        tmpl.id.clone()
                    } else {
                        tmpl.info.name.clone()
                    },
                    severity: if tmpl.info.severity.is_empty() {
                        "info".to_string()
                    } else {
                        tmpl.info.severity.clone()
                    },
                    description,
                    matched_at: winner.url.clone(),
                });
            }
        }
    }
    out
}

fn substitute_oob(s: &str, host: &str) -> String {
    s.replace("{{interactsh-url}}", host)
        .replace("{{oast-url}}", host)
}

/// A concrete request produced by expanding one template request's payloads.
#[derive(Clone)]
struct ReqVariant {
    url: String,
    headers: Vec<(String, String)>,
    body: Option<String>,
}

/// Expand `{{BaseURL}}` in the path, then substitute any `{{payloadName}}`
/// placeholders (in the URL, the body, and header values) from `payloads`,
/// generating a capped cartesian product of concrete requests. A payload
/// referenced only in the body/headers (not the URL) is still expanded.
fn expand_request(req: &HttpReq, raw_path: &str, base: &str, cap: usize) -> Vec<ReqVariant> {
    let headers0: Vec<(String, String)> = req
        .headers
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let base_variant = ReqVariant {
        url: expand(raw_path, base),
        headers: headers0,
        body: req.body.clone(),
    };

    if req.payloads.is_empty() {
        return vec![base_variant];
    }
    // A payload key matters if it is referenced anywhere in the request.
    let mut hay = base_variant.url.clone();
    if let Some(b) = &base_variant.body {
        hay.push(' ');
        hay.push_str(b);
    }
    for (k, v) in &base_variant.headers {
        hay.push(' ');
        hay.push_str(k);
        hay.push_str(v);
    }
    let referenced: Vec<(&String, &Vec<String>)> = req
        .payloads
        .iter()
        .filter(|(k, _)| hay.contains(&format!("{{{{{k}}}}}")))
        .collect();
    if referenced.is_empty() {
        return vec![base_variant];
    }
    let mut results = vec![base_variant];
    for (k, vals) in referenced {
        let placeholder = format!("{{{{{k}}}}}");
        let mut next = Vec::new();
        'outer: for cur in &results {
            for val in vals {
                let mut nv = cur.clone();
                nv.url = nv.url.replace(&placeholder, val);
                if let Some(b) = &mut nv.body {
                    *b = b.replace(&placeholder, val);
                }
                for (_, hv) in nv.headers.iter_mut() {
                    *hv = hv.replace(&placeholder, val);
                }
                next.push(nv);
                if next.len() >= cap {
                    break 'outer;
                }
            }
        }
        results = next;
        if results.len() >= cap {
            results.truncate(cap);
            break;
        }
    }
    results
}

/// Substitute OOB (interactsh) markers with the OAST host across url/body/headers.
fn apply_oob(v: &mut ReqVariant, host: &str) {
    v.url = substitute_oob(&v.url, host);
    if let Some(b) = &mut v.body {
        *b = substitute_oob(b, host);
    }
    for (_, hv) in v.headers.iter_mut() {
        *hv = substitute_oob(hv, host);
    }
}

/// Issue a request over the raw sender (verbatim path, no dot-segment
/// normalisation) and adapt it to the same `Resp` the matchers expect.
/// Send a variant over the appropriate transport: the raw sender for `unsafe`
/// templates (verbatim request-target), reqwest otherwise.
async fn send_variant(
    client: &Client,
    method: &str,
    unsafe_raw: bool,
    v: &ReqVariant,
) -> Option<Resp> {
    if unsafe_raw {
        fetch_raw(method, v).await
    } else {
        fetch(client, method, v).await
    }
}

/// True when a response looks like a WAF/anti-bot challenge or block rather than
/// the app's own answer, so a payload-encoding retry is warranted.
fn resp_is_blocked(r: &Resp) -> bool {
    adaptive::challenge::detect(
        r.status,
        |n| {
            r.headers.lines().find_map(|l| {
                l.split_once(':').and_then(|(k, val)| {
                    k.trim()
                        .eq_ignore_ascii_case(n)
                        .then(|| val.trim().to_string())
                })
            })
        },
        &r.body,
    )
    .is_challenge()
}

async fn fetch_raw(method: &str, v: &ReqVariant) -> Option<Resp> {
    let r = crate::rawhttp::send(crate::rawhttp::RawReq {
        method,
        url: &v.url,
        headers: &v.headers,
        body: v.body.clone(),
        timeout: std::time::Duration::from_secs(10),
    })
    .await?;
    Some(Resp {
        status: r.status,
        headers: r.headers,
        body: r.body,
        url: v.url.clone(),
    })
}

async fn fetch(client: &Client, method: &str, v: &ReqVariant) -> Option<Resp> {
    // Rate-limit resilience: a busy or WAF/edge-fronted target answers a burst of
    // template requests with 429/503. Without a retry, the later templates in a
    // scan silently miss (false negatives). Retry with backoff (honoring a small
    // Retry-After) so detection is not a function of how fast we happened to scan.
    let mut attempt: u32 = 0;
    loop {
        let mut rb = match method {
            "POST" => client.post(&v.url),
            "HEAD" => client.head(&v.url),
            "PUT" => client.put(&v.url),
            "PATCH" => client.patch(&v.url),
            "DELETE" => client.delete(&v.url),
            _ => client.get(&v.url),
        };
        for (k, val) in &v.headers {
            rb = rb.header(k.as_str(), val.as_str());
        }
        if let Some(b) = &v.body {
            rb = rb.body(b.clone());
        }
        match rb.send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                if (status == 429 || status == 503) && attempt < 5 {
                    let wait = retry_after_ms(r.headers(), attempt);
                    tokio::time::sleep(std::time::Duration::from_millis(wait)).await;
                    attempt += 1;
                    continue;
                }
                let mut headers = String::new();
                for (k, vv) in r.headers().iter() {
                    headers.push_str(k.as_str());
                    headers.push_str(": ");
                    headers.push_str(vv.to_str().unwrap_or(""));
                    headers.push('\n');
                }
                let body = crate::engine::read_body_capped(r).await;
                return Some(Resp {
                    status,
                    headers,
                    body,
                    url: v.url.clone(),
                });
            }
            Err(_) => {
                // Transient connection error: one or two quick retries.
                if attempt < 2 {
                    tokio::time::sleep(std::time::Duration::from_millis(
                        300 * (attempt as u64 + 1),
                    ))
                    .await;
                    attempt += 1;
                    continue;
                }
                return None;
            }
        }
    }
}

/// Backoff for a 429/503: honor a small integer `Retry-After`, else exponential
/// (0.4s, 0.8s, 1.6s, 3.2s, capped at 4s).
fn retry_after_ms(headers: &reqwest::header::HeaderMap, attempt: u32) -> u64 {
    if let Some(secs) = headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
    {
        return (secs * 1000).clamp(200, 5000);
    }
    (400u64 << attempt.min(4)).min(4000)
}

fn matches_all(req: &HttpReq, resp: &Resp) -> bool {
    if req.matchers.is_empty() {
        return false;
    }
    let cond_and = req.matchers_condition.to_lowercase() != "or";
    let mut any = false;
    let mut all = true;
    for m in &req.matchers {
        let mut matched = matches_one(m, resp);
        if m.negative {
            matched = !matched;
        }
        any = any || matched;
        all = all && matched;
    }
    if cond_and { all } else { any }
}

/// Does this response simply echo the requested path back into its body?
///
/// Catch-all handlers, soft 404s and "page not found" templates routinely do
/// this. When they do, any matcher word that also appears in the request URL is
/// worthless as evidence: the scanner put it there. A WebLogic template probing
/// `/console/css/..%2fconsole.portal` and matching the word "console.portal"
/// will otherwise fire on every app in the world that prints the path it could
/// not find, which is how a 200-line Python app got reported as a critical
/// Oracle WebLogic auth bypass.
///
/// Deliberately narrow. Evidence is only discounted on responses that provably
/// echo, so a real WebLogic console still matches on "WebLogic" and
/// "Deployment", and templates whose words legitimately appear in the path keep
/// working everywhere else.
fn echoes_request_path(resp: &Resp) -> bool {
    let path = match resp.url.split_once("://") {
        Some((_, rest)) => match rest.find('/') {
            Some(i) => &rest[i..],
            None => return false,
        },
        None => return false,
    };
    let path = path.split(['?', '#']).next().unwrap_or("");
    let trimmed = path.trim_matches('/');
    if trimmed.len() < 4 {
        return false;
    }
    let body = resp.body.to_lowercase();
    let needle = trimmed.to_lowercase();
    if body.contains(&needle) {
        return true;
    }
    // Also catch the percent-decoded form, since a traversal payload is usually
    // encoded on the wire and printed decoded.
    let decoded = needle.replace("%252e", ".").replace("%2e", ".").replace("%252f", "/").replace("%2f", "/");
    decoded != needle && body.contains(&decoded)
}

fn matches_one(m: &Matcher, resp: &Resp) -> bool {
    let hay = part_text(&m.part, resp);
    match m.mtype.as_str() {
        "status" => m.status.contains(&resp.status),
        "size" => m.size.contains(&resp.body.len()),
        "word" => {
            if m.words.is_empty() {
                return false;
            }
            let cond_and = m.condition.to_lowercase() != "or";
            // Header names are normalized to lowercase by the HTTP client, so match
            // the header/all_headers part case-insensitively. This keeps cortex
            // compatible with nuclei templates that spell header names in canonical
            // case (e.g. "Server:", "X-Powered-By:"), which would otherwise miss.
            let header_part = matches!(m.part.as_str(), "header" | "all_headers");
            let hay_cmp = if header_part { hay.to_lowercase() } else { hay };
            // On a response that echoes the request path, a word that is itself
            // in the URL proves nothing. Only applied to body-ish parts, and
            // only when the echo is demonstrated.
            let discount_echo = !header_part && echoes_request_path(resp);
            let url_lc = resp.url.to_lowercase();
            let contains = |w: &str| {
                if discount_echo && url_lc.contains(&w.to_lowercase()) {
                    return false;
                }
                if header_part {
                    hay_cmp.contains(&w.to_lowercase())
                } else {
                    hay_cmp.contains(w)
                }
            };
            if cond_and {
                m.words.iter().all(|w| contains(w.as_str()))
            } else {
                m.words.iter().any(|w| contains(w.as_str()))
            }
        }
        "regex" => {
            if m.regex.is_empty() {
                return false;
            }
            let cond_and = m.condition.to_lowercase() != "or";
            let mut any = false;
            let mut all = true;
            for p in &m.regex {
                let matched = Regex::new(p).map(|re| re.is_match(&hay)).unwrap_or(false);
                any = any || matched;
                all = all && matched;
            }
            if cond_and { all } else { any }
        }
        "dsl" => {
            if m.dsl.is_empty() {
                return false;
            }
            let ctx = crate::dsl::Ctx {
                status_code: resp.status,
                body: &resp.body,
                headers: &resp.headers,
                content_length: resp.body.len(),
            };
            let cond_and = m.condition.to_lowercase() != "or";
            let mut any = false;
            let mut all = true;
            for expr in &m.dsl {
                let matched = crate::dsl::eval_bool(expr, &ctx);
                any = any || matched;
                all = all && matched;
            }
            if cond_and { all } else { any }
        }
        _ => false,
    }
}

fn part_text(part: &str, resp: &Resp) -> String {
    match part {
        "header" | "all_headers" => resp.headers.clone(),
        "all" | "raw" | "response" => format!("{}\n{}\n{}", resp.status, resp.headers, resp.body),
        _ => resp.body.clone(),
    }
}

fn expand(path: &str, base: &str) -> String {
    let base_trimmed = base.trim_end_matches('/');
    let host = base_trimmed
        .split("://")
        .nth(1)
        .and_then(|s| s.split('/').next())
        .unwrap_or(base_trimmed);
    let mut p = path
        .replace("{{BaseURL}}", base_trimmed)
        .replace("{{RootURL}}", base_trimmed)
        .replace("{{Hostname}}", host);
    if !p.contains("://") {
        if p.starts_with('/') {
            p = format!("{base_trimmed}{p}");
        } else {
            p = format!("{base_trimmed}/{p}");
        }
    }
    p
}

// ---------------------------------------------------------------------------
// Built-in templates (embedded). A small, high-signal starter set; the executor
// also loads external nuclei templates from a directory when configured.
// ---------------------------------------------------------------------------

const BUILTIN_YAML: &[&str] = &[
    r#"
id: git-config-exposure
info:
  name: Exposed .git/config
  severity: medium
  description: A publicly readable .git/config can leak source, credentials, and internal remotes.
http:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "[core]"
          - "repositoryformatversion"
        condition: and
      - type: status
        status:
          - 200
"#,
    r#"
id: dotenv-exposure
info:
  name: Exposed .env file
  severity: high
  description: A publicly readable .env file commonly exposes application secrets and DB credentials.
http:
  - method: GET
    path:
      - "{{BaseURL}}/.env"
    matchers-condition: and
    matchers:
      - type: regex
        part: body
        regex:
          - "(?m)^\\s*(APP_KEY|DB_PASSWORD|SECRET_KEY|AWS_SECRET_ACCESS_KEY)\\s*="
      - type: status
        status:
          - 200
"#,
    r#"
id: phpinfo-exposure
info:
  name: Exposed phpinfo()
  severity: low
  description: A reachable phpinfo() page discloses environment, paths, and module configuration.
http:
  - method: GET
    path:
      - "{{BaseURL}}/phpinfo.php"
      - "{{BaseURL}}/info.php"
    matchers-condition: and
    matchers:
      # "PHP Version" alone appears in ordinary prose; require a second phpinfo()
      # structural marker so an article mentioning "PHP Version" is not flagged.
      - type: word
        part: body
        words:
          - "PHP Version"
      - type: word
        part: body
        words:
          - "phpinfo()"
          - "Configuration File (php.ini)"
          - "PHP License"
          - "PHP Credits"
        condition: or
      - type: status
        status:
          - 200
"#,
    r#"
id: apache-server-status
info:
  name: Exposed Apache server-status
  severity: low
  description: mod_status exposes request and worker information to unauthenticated clients.
http:
  - method: GET
    path:
      - "{{BaseURL}}/server-status"
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "Apache Server Status"
      - type: status
        status:
          - 200
"#,
    r#"
id: directory-listing
info:
  name: Directory listing enabled
  severity: info
  description: An auto-index directory listing can expose files not meant to be enumerable.
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "Index of /"
          - "<title>Index of"
        condition: or
      # A real autoindex also renders navigable file links; requiring one avoids
      # flagging pages that merely contain the phrase "Index of /" in prose.
      - type: word
        part: body
        words:
          - "Parent Directory"
          - "<a href="
          - "[DIR]"
        condition: or
      - type: status
        status:
          - 200
"#,
    r#"
id: env-bak-exposure
info:
  name: Exposed .env backup
  severity: high
  description: A backup copy of the environment file can leak the same secrets as the live file.
http:
  - method: GET
    path:
      - "{{BaseURL}}/.env.bak"
      - "{{BaseURL}}/.env.save"
    matchers-condition: and
    matchers:
      - type: regex
        part: body
        regex:
          - "(?m)^\\s*(APP_KEY|DB_PASSWORD|SECRET_KEY)\\s*="
      - type: status
        status:
          - 200
"#,
    r#"
id: exposed-private-key
info:
  name: Exposed SSH/TLS private key
  severity: critical
  description: A publicly readable private key allows full server impersonation and compromise.
http:
  - method: GET
    path:
      - "{{BaseURL}}/id_rsa"
      - "{{BaseURL}}/.ssh/id_rsa"
      - "{{BaseURL}}/server.key"
      - "{{BaseURL}}/private.pem"
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "-----BEGIN RSA PRIVATE KEY-----"
          - "-----BEGIN OPENSSH PRIVATE KEY-----"
          - "-----BEGIN PRIVATE KEY-----"
          - "-----BEGIN EC PRIVATE KEY-----"
        condition: or
      - type: status
        status:
          - 200
"#,
    r#"
id: exposed-aws-credentials
info:
  name: Exposed AWS credentials
  severity: critical
  description: AWS secret keys exposed in a reachable file grant direct access to cloud infrastructure.
http:
  - method: GET
    path:
      - "{{BaseURL}}/.env"
      - "{{BaseURL}}/.aws/credentials"
    matchers-condition: and
    matchers:
      - type: regex
        part: body
        regex:
          - "(?i)aws_secret_access_key\\s*[=:]\\s*[A-Za-z0-9/+=]{40}"
      - type: status
        status:
          - 200
"#,
    r#"
id: debug-stacktrace-disclosure
info:
  name: Application debug stack trace disclosed
  severity: medium
  description: A debug or exception page discloses framework internals, file paths, and sometimes secrets. Demonstrates the dsl matcher.
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: dsl
        dsl:
          - "contains(body, 'Traceback (most recent call last)') || contains(body, 'Whoops, looks like something went wrong') || (contains(body, 'Exception') && contains(body, 'stack trace')) || icontains(body, 'Werkzeug Debugger')"
"#,
    r#"
id: path-traversal-lfi
info:
  name: Local file inclusion / path traversal
  severity: high
  description: A path that returns the contents of /etc/passwd indicates local file inclusion. Demonstrates payload fuzzing.
http:
  - method: GET
    unsafe: true
    payloads:
      trav:
        - "../../../../../../etc/passwd"
        - "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd"
        - "....//....//....//....//etc/passwd"
    attack: batteringram
    path:
      - "{{BaseURL}}/{{trav}}"
    matchers-condition: and
    matchers:
      - type: regex
        part: body
        regex:
          - "root:.*:0:0:"
      - type: status
        status:
          - 200
"#,
    r#"
id: blind-ssrf-oob
info:
  name: Blind server-side request forgery (out-of-band)
  severity: high
  description: A parameter that makes the server fetch an attacker-controlled URL indicates SSRF. Requires a configured OAST server; confirmed by an out-of-band callback.
http:
  - method: GET
    path:
      - "{{BaseURL}}/?url=http://{{interactsh-url}}"
      - "{{BaseURL}}/?uri=http://{{interactsh-url}}"
      - "{{BaseURL}}/?dest=http://{{interactsh-url}}"
      - "{{BaseURL}}/?redirect_uri=http://{{interactsh-url}}"
      - "{{BaseURL}}/?callback=http://{{interactsh-url}}"
      - "{{BaseURL}}/?webhook=http://{{interactsh-url}}"
"#,
    r#"
id: database-backup-exposure
info:
  name: Exposed database backup
  severity: critical
  description: A downloadable SQL dump exposes the full database, including password hashes and credentials.
http:
  - method: GET
    path:
      - "{{BaseURL}}/db_backup.sql"
      - "{{BaseURL}}/dump.sql"
      - "{{BaseURL}}/database.sql"
      - "{{BaseURL}}/backup.sql"
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "CREATE TABLE"
          - "INSERT INTO"
          - "MySQL dump"
        condition: or
      - type: status
        status:
          - 200
"#,
];

pub static BUILTIN: LazyLock<Vec<Template>> = LazyLock::new(|| {
    BUILTIN_YAML
        .iter()
        .filter_map(|y| serde_yaml::from_str::<Template>(y).ok())
        .collect()
});

/// Load external nuclei templates (*.yaml / *.yml) from a directory, recursing
/// into subdirectories so a categorized pack (technologies/, exposures/, cves/,
/// ...) loads as one set. Templates that fail to parse against the supported
/// subset, or carry no runnable request, are skipped rather than aborting the
/// load. A hidden directory (leading dot) is skipped so stray editor/VCS state
/// is never walked.
pub fn load_dir(dir: &str) -> Vec<Template> {
    let mut out = Vec::new();
    load_dir_into(std::path::Path::new(dir), &mut out);
    out
}

fn load_dir_into(dir: &std::path::Path, out: &mut Vec<Template>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let hidden = path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with('.'))
                .unwrap_or(false);
            if !hidden {
                load_dir_into(&path, out);
            }
            continue;
        }
        let is_yaml = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e == "yaml" || e == "yml")
            .unwrap_or(false);
        if !is_yaml {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&path)
            && let Ok(t) = serde_yaml::from_str::<Template>(&text)
            && !t.http.is_empty()
        {
            out.push(t);
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn all_builtins_parse() {
        // Every embedded template must parse against the supported subset;
        // filter_map would otherwise silently drop a malformed one.
        assert_eq!(
            super::BUILTIN.len(),
            super::BUILTIN_YAML.len(),
            "a builtin template failed to parse"
        );
        assert!(super::BUILTIN.iter().any(|t| t.id == "path-traversal-lfi"));
        assert!(
            super::BUILTIN
                .iter()
                .any(|t| t.id == "debug-stacktrace-disclosure")
        );
    }

    #[test]
    fn dsl_matcher_wired() {
        // The dsl matcher path is reachable and evaluates the response context.
        let resp = super::Resp {
            url: String::new(),
            status: 200,
            headers: "Server: nginx\n".to_string(),
            body: "Werkzeug Debugger traceback".to_string(),
        };
        let m = super::Matcher {
            mtype: "dsl".to_string(),
            part: String::new(),
            words: vec![],
            regex: vec![],
            status: vec![],
            size: vec![],
            dsl: vec!["status_code == 200 && icontains(body, 'werkzeug')".to_string()],
            condition: "and".to_string(),
            negative: false,
        };
        assert!(super::matches_one(&m, &resp));
    }
}

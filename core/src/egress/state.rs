//! Where this node's scans and Bench requests leave from, and the lease each op takes
//! when they leave through a proxy.
//!
//! The platform says which in an `egress` object: in the authorize-node answer at
//! start, and from the node-facing settings route (`POST /api/v1/node-egress`)
//! whenever it announces a change, an op expects settings newer than the node's, the
//! node's NATS connection comes back, and once a minute besides. The object carries the
//! proxy's credentials, so it never travels over NATS.
//!
//! Every way of being unsure ends with the op refused rather than sent from the node's
//! own address: settings the node could not fetch, settings it cannot read, a proxy
//! other than the one the op was dispatched for, and an op that expects a proxy on a
//! node that no longer has one.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use cfx_tunnel::{Kind, Upstream};
use serde_json::{Value, json};

use super::gateway::{Gateway, Lease, Resolver, system_resolver};

/// The version of the `egress` object this node reads.
pub const SETTINGS_VERSION: i64 = 1;

/// The gateway this node runs, as the heartbeat reports it. The platform does not send
/// a proxied op to a node whose heartbeat lacks it.
pub const GATEWAY_VERSION: u32 = 1;

/// The page a node-side proxy check fetches. Cloudflare's trace on our own zone
/// answers with the address the request came from, as `ip=`.
pub const CHECK_URL: &str = "https://crossfyre.io/cdn-cgi/trace";

/// How long a settings fetch may take.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// After a failed fetch, ops in this window are refused with its error instead of each
/// asking again. A scan dispatched as thousands of ops would otherwise queue a fetch
/// per op behind a control plane that is not answering.
const RETRY_AFTER: Duration = Duration::from_secs(5);

/// How often the node asks for its settings with no change announced. The platform
/// announces a change over NATS, and an announcement sent while the node is
/// reconnecting is lost; nothing else would tell the node.
pub const POLL_EVERY: Duration = Duration::from_secs(60);

/// How long a node-side proxy check may take, end to end.
const CHECK_TIMEOUT: Duration = Duration::from_secs(15);

/// Refusal when an op was dispatched for a proxy this node no longer sends through.
pub const NOT_THAT_PROXY: &str = "this node is no longer set to send through that proxy";

/// What the platform set this node's egress to.
#[derive(Clone, Debug)]
pub enum Setting {
    /// Scans leave from the node's own address, as before this step.
    Direct,
    /// Through this proxy, by the platform's id for it.
    Proxy { id: String, upstream: Arc<Upstream> },
    /// The platform named a proxy this node cannot use. Every op is refused with this.
    Unusable(String),
}

#[derive(Clone, Debug)]
pub struct NodeEgress {
    /// The platform's revision of these settings. Higher is newer.
    pub rev: i64,
    pub setting: Setting,
}

impl NodeEgress {
    pub fn direct() -> NodeEgress {
        NodeEgress {
            rev: 0,
            setting: Setting::Direct,
        }
    }

    /// Reads the platform's `egress` object:
    /// `{"v":1,"rev":7,"mode":"proxy","proxy":{"id","type","host","port","username","password"}}`
    /// or `{"v":1,"rev":0,"mode":"direct","proxy":null}`.
    ///
    /// An object without a readable version, revision or mode is an error. A readable
    /// one in proxy mode whose proxy cannot be used comes back as
    /// [`Setting::Unusable`], since asking again would only give the same answer.
    pub fn from_wire(v: &Value) -> Result<NodeEgress, String> {
        let o = v
            .as_object()
            .ok_or("the egress settings are not an object")?;
        let ver = o
            .get("v")
            .and_then(Value::as_i64)
            .ok_or("the egress settings have no version")?;
        if ver != SETTINGS_VERSION {
            return Err(format!(
                "egress settings version {ver} is not one this node reads (it reads \
                 {SETTINGS_VERSION}). Run `crossfyre update`"
            ));
        }
        let rev = o
            .get("rev")
            .and_then(Value::as_i64)
            .ok_or("the egress settings have no revision")?;
        let setting = match o.get("mode").and_then(Value::as_str) {
            Some("direct") => Setting::Direct,
            Some("proxy") => match o.get("proxy").filter(|p| !p.is_null()).map(read_proxy) {
                Some(Ok((id, upstream))) => Setting::Proxy {
                    id,
                    upstream: Arc::new(upstream),
                },
                Some(Err(why)) => {
                    Setting::Unusable(format!("this node's proxy cannot be used: {why}"))
                }
                // The platform could not hand the proxy over: it is gone, its
                // credentials do not open, or it breaks a rule a node checks.
                None => Setting::Unusable(
                    "this node is set to send through a proxy the platform could not hand over"
                        .into(),
                ),
            },
            Some(other) => return Err(format!("egress mode {other:?} is not one this node knows")),
            None => return Err("the egress settings have no mode".into()),
        };
        Ok(NodeEgress { rev, setting })
    }

    /// `"direct"` or `"proxy"`. Settings that name an unusable proxy are still proxy
    /// mode: they are what the platform asked for.
    pub fn mode(&self) -> &'static str {
        match self.setting {
            Setting::Direct => "direct",
            Setting::Proxy { .. } | Setting::Unusable(_) => "proxy",
        }
    }

    pub fn proxy_id(&self) -> Option<&str> {
        match &self.setting {
            Setting::Proxy { id, .. } => Some(id),
            _ => None,
        }
    }
}

/// Reads one `proxy` object into the platform's id for it and an [`Upstream`]. The
/// error never quotes a credential.
pub fn read_proxy(p: &Value) -> Result<(String, Upstream), String> {
    let o = p.as_object().ok_or("the proxy is not an object")?;
    let id = o
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or("the proxy has no id")?;
    let kind = match o.get("type").and_then(Value::as_str) {
        Some("http") => Kind::Http,
        Some("https") => Kind::Https,
        Some("socks4" | "socks4a") => Kind::Socks4,
        Some("socks5" | "socks5h") => Kind::Socks5,
        Some(other) => return Err(format!("proxy type {other:?} is not one this node speaks")),
        None => return Err("the proxy has no type".into()),
    };
    let host = o
        .get("host")
        .and_then(Value::as_str)
        .map(|h| h.trim_start_matches('[').trim_end_matches(']'))
        .filter(|h| !h.is_empty())
        .ok_or("the proxy has no host")?;
    let port = o
        .get("port")
        .and_then(Value::as_u64)
        .and_then(|p| u16::try_from(p).ok())
        .filter(|&p| p != 0)
        .ok_or("the proxy port is not 1 to 65535")?;
    let text = |k: &str| -> Result<String, String> {
        match o.get(k) {
            None | Some(Value::Null) => Ok(String::new()),
            Some(Value::String(s)) => Ok(s.clone()),
            Some(_) => Err(format!("the proxy {k} is not text")),
        }
    };
    let (user, pass) = (text("username")?, text("password")?);
    let auth = match (user.is_empty(), pass.is_empty()) {
        (true, true) => None,
        (true, false) => return Err("the proxy has a password and no user name".into()),
        (false, _) => Some((user, pass)),
    };
    let up = Upstream {
        kind,
        host: host.to_string(),
        port,
        auth,
    };
    up.check()?;
    Ok((id.to_string(), up))
}

/// What an op was dispatched expecting of this node, from `egress_expect`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expect {
    pub proxy_id: Option<String>,
    pub rev: i64,
}

impl Expect {
    /// `{"mode":"proxy","proxy_id":"...","rev":7}` or `{"mode":"direct","rev":7}`.
    /// Absent (an older dispatch path, or a resume) is `None`. Present and unreadable is
    /// an error, and the op is refused with it.
    pub fn read(v: &Value) -> Result<Option<Expect>, String> {
        if v.is_null() {
            return Ok(None);
        }
        let bad = "the operation's proxy expectation cannot be read";
        let o = v.as_object().ok_or(bad)?;
        let rev = o.get("rev").and_then(Value::as_i64).ok_or(bad)?;
        let proxy_id = match o.get("mode").and_then(Value::as_str) {
            Some("direct") => None,
            Some("proxy") => Some(
                o.get("proxy_id")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .ok_or(bad)?
                    .to_string(),
            ),
            _ => return Err(bad.into()),
        };
        Ok(Some(Expect { proxy_id, rev }))
    }
}

/// How the node reaches the control plane for its settings.
pub struct Fetch<'a> {
    pub http: &'a reqwest::Client,
    pub api_url: &'a str,
    pub api_key: &'a str,
}

/// Why the node knows it may be behind the platform.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stale {
    /// The platform has this revision and the node has not fetched it.
    Rev(i64),
    /// The node cannot tell which revision the platform has: the last settings it got
    /// could not be read, a change was announced without one, or the node's NATS
    /// connection dropped, and a change announced meanwhile was lost.
    Unsure,
}

/// This node's egress settings and its gateway. The daemon holds one ([`global`]);
/// tests make their own.
pub struct EgressState {
    /// A channel rather than a lock, so work that started direct can wait for the node
    /// to stop being direct.
    current: tokio::sync::watch::Sender<NodeEgress>,
    stale: Mutex<Option<Stale>>,
    last_failure: Mutex<Option<(Instant, String)>>,
    refreshing: tokio::sync::Mutex<()>,
    gateway: tokio::sync::OnceCell<Arc<Gateway>>,
    resolver: Resolver,
    /// Whether the platform has shown it keeps egress settings for this node. A
    /// controller older than proxies has no route to fetch them from, so its nodes
    /// never ask, and stay direct as they always were.
    platform_has_settings: AtomicBool,
}

/// The daemon's state. Each node runs as its own process, so one per process is one
/// per node.
pub fn global() -> &'static Arc<EgressState> {
    static STATE: OnceLock<Arc<EgressState>> = OnceLock::new();
    STATE.get_or_init(|| EgressState::new(system_resolver()))
}

impl EgressState {
    pub fn new(resolver: Resolver) -> Arc<EgressState> {
        Arc::new(EgressState {
            current: tokio::sync::watch::Sender::new(NodeEgress::direct()),
            stale: Mutex::new(None),
            last_failure: Mutex::new(None),
            refreshing: tokio::sync::Mutex::new(()),
            gateway: tokio::sync::OnceCell::new(),
            resolver,
            platform_has_settings: AtomicBool::new(false),
        })
    }

    pub fn current(&self) -> NodeEgress {
        self.current.borrow().clone()
    }

    fn set(&self, n: NodeEgress) {
        self.current.send_replace(n);
    }

    fn stale(&self) -> Option<Stale> {
        self.stale.lock().map(|s| *s).unwrap_or(Some(Stale::Unsure))
    }

    fn mark_stale(&self, s: Stale) {
        if let Ok(mut cur) = self.stale.lock() {
            *cur = match (*cur, s) {
                (Some(Stale::Unsure), _) | (_, Stale::Unsure) => Some(Stale::Unsure),
                (Some(Stale::Rev(a)), Stale::Rev(b)) => Some(Stale::Rev(a.max(b))),
                (None, s) => Some(s),
            };
        }
    }

    /// Takes the `egress` field of the authorize-node answer. An answer without one
    /// comes from a controller older than proxies, and means direct. One the node
    /// cannot read leaves every op refused until a fetch succeeds.
    pub fn apply_authorize(&self, v: &Value) {
        if v.is_null() {
            self.set(NodeEgress::direct());
            if let Ok(mut s) = self.stale.lock() {
                *s = None;
            }
            return;
        }
        self.platform_has_settings.store(true, Ordering::Relaxed);
        match NodeEgress::from_wire(v) {
            Ok(n) => {
                self.say_applied(&n);
                self.set(n);
                if let Ok(mut s) = self.stale.lock() {
                    *s = None;
                }
            }
            Err(e) => {
                eprintln!("[egress] the platform's egress settings cannot be read: {e}");
                let rev = self.current().rev;
                self.set(NodeEgress {
                    rev,
                    setting: Setting::Unusable(format!(
                        "this node's proxy settings cannot be read: {e}"
                    )),
                });
                self.mark_stale(Stale::Unsure);
            }
        }
    }

    fn say_applied(&self, n: &NodeEgress) {
        match &n.setting {
            Setting::Direct => println!("[egress] scans leave from this node's own address."),
            Setting::Proxy { upstream, .. } => println!(
                "[egress] scans and Bench requests leave through {} (settings rev {}).",
                upstream.label(),
                n.rev
            ),
            Setting::Unusable(why) => {
                eprintln!("[egress] {why}. Scans are refused until it is fixed.")
            }
        }
    }

    /// The platform says its settings for this node changed, to revision `rev` when it
    /// says which. Until they are fetched, ops are refused rather than run on the old
    /// ones.
    pub fn announce(&self, rev: Option<i64>) {
        self.platform_has_settings.store(true, Ordering::Relaxed);
        match rev {
            Some(r) if r <= self.current().rev => {}
            Some(r) => self.mark_stale(Stale::Rev(r)),
            None => self.mark_stale(Stale::Unsure),
        }
    }

    /// Fetch the settings now, whatever the node has. On failure the node keeps what
    /// it had and remembers that it is behind.
    pub async fn refresh(&self, f: &Fetch<'_>) -> Result<NodeEgress, String> {
        let _g = self.refreshing.lock().await;
        self.fetch_and_apply(f).await
    }

    async fn fetch_and_apply(&self, f: &Fetch<'_>) -> Result<NodeEgress, String> {
        let got = match post_settings(f, json!({"proxy_id": null, "test_id": null})).await {
            Ok(data) => NodeEgress::from_wire(&data),
            Err(e) => Err(e),
        };
        match got {
            Ok(n) => {
                self.platform_has_settings.store(true, Ordering::Relaxed);
                if let Ok(mut last) = self.last_failure.lock() {
                    *last = None;
                }
                if let Ok(mut s) = self.stale.lock() {
                    *s = match *s {
                        Some(Stale::Rev(r)) if r > n.rev => Some(Stale::Rev(r)),
                        _ => None,
                    };
                }
                let changed = {
                    let cur = self.current();
                    cur.rev != n.rev || cur.mode() != n.mode() || cur.proxy_id() != n.proxy_id()
                };
                if changed {
                    self.say_applied(&n);
                }
                self.set(n.clone());
                Ok(n)
            }
            Err(e) => {
                self.remember_failure(&e);
                Err(e)
            }
        }
    }

    /// The settings an op may run under: the node's own, fetched again first when the
    /// op expects a newer revision or the node knows it is behind.
    async fn fresh(&self, want_rev: Option<i64>, f: &Fetch<'_>) -> Result<NodeEgress, String> {
        let behind = |cur: &NodeEgress, stale: Option<Stale>| {
            want_rev.is_some_and(|w| w > cur.rev)
                || match stale {
                    Some(Stale::Unsure) => true,
                    Some(Stale::Rev(r)) => r > cur.rev,
                    None => false,
                }
        };
        let cur = self.current();
        if !behind(&cur, self.stale()) {
            return Ok(cur);
        }
        let _g = self.refreshing.lock().await;
        // Another op may have fetched while this one waited.
        let cur = self.current();
        if !behind(&cur, self.stale()) {
            return Ok(cur);
        }
        let recent = self
            .last_failure
            .lock()
            .ok()
            .and_then(|f| f.clone())
            .filter(|(at, _)| at.elapsed() < RETRY_AFTER);
        let fetched = match recent {
            Some((_, e)) => Err(e),
            None => self.fetch_and_apply(f).await,
        };
        if let Err(e) = fetched {
            if let Some(w) = want_rev {
                self.mark_stale(Stale::Rev(w));
            }
            return Err(format!("could not fetch this node's proxy settings: {e}"));
        }
        let cur = self.current();
        let still_behind = if let Some(w) = want_rev
            && w > cur.rev
        {
            Some(format!(
                "this node's proxy settings (rev {}) are older than the ones this operation \
                 was sent with (rev {w})",
                cur.rev
            ))
        } else if behind(&cur, self.stale()) {
            Some(format!(
                "this node's proxy settings (rev {}) are behind the platform's",
                cur.rev
            ))
        } else {
            None
        };
        match still_behind {
            // The platform answered with settings older than it said it has. Asking
            // again at once would get the same answer, so the next ops wait as after a
            // failed fetch.
            Some(e) => {
                self.remember_failure(&e);
                Err(e)
            }
            None => Ok(cur),
        }
    }

    fn remember_failure(&self, e: &str) {
        if let Ok(mut last) = self.last_failure.lock() {
            *last = Some((Instant::now(), e.to_string()));
        }
    }

    /// Which proxy, if any, an op with this expectation sends through.
    async fn decide(
        &self,
        want: Option<&Expect>,
        f: &Fetch<'_>,
    ) -> Result<Option<(String, Arc<Upstream>)>, String> {
        let now = self.fresh(want.map(|w| w.rev), f).await?;
        let want_proxy = want.and_then(|w| w.proxy_id.as_deref());
        match now.setting {
            Setting::Unusable(why) => Err(why),
            Setting::Proxy { id, .. } if want_proxy.is_some_and(|w| w != id) => {
                Err(NOT_THAT_PROXY.into())
            }
            // Newer node settings win over an op that expected direct: the direction
            // of any error is toward the proxy.
            Setting::Proxy { id, upstream } => Ok(Some((id, upstream))),
            Setting::Direct if want_proxy.is_some() => Err(NOT_THAT_PROXY.into()),
            Setting::Direct => Ok(None),
        }
    }

    /// The lease a dispatched op runs under: `None` on a direct node, as before. An
    /// error refuses the op with its text.
    pub async fn for_op(
        &self,
        op_id: &str,
        node_id: &str,
        data: &Value,
        f: &Fetch<'_>,
    ) -> Result<Option<Arc<Lease>>, String> {
        let want = Expect::read(&data["egress_expect"][node_id])?;
        let Some((id, upstream)) = self.decide(want.as_ref(), f).await? else {
            return Ok(None);
        };
        let block_internal = data["block_internal"].as_bool().unwrap_or(false);
        self.lease(op_id, &id, upstream, block_internal)
            .await
            .map(|l| Some(Arc::new(l)))
    }

    /// The lease a Bench send goes out under. Its `egress_expect` has no node key, and
    /// its destination is vetted on the node as the platform vetted it: no private
    /// address.
    pub async fn for_bench(&self, cmd: &Value, f: &Fetch<'_>) -> Result<Option<Lease>, String> {
        let want = Expect::read(&cmd["egress_expect"])?;
        let Some((id, upstream)) = self.decide(want.as_ref(), f).await? else {
            return Ok(None);
        };
        let op = format!("bench {}", cmd["command_id"].as_str().unwrap_or(""));
        self.lease(&op, &id, upstream, true).await.map(Some)
    }

    async fn lease(
        &self,
        op: &str,
        proxy_id: &str,
        upstream: Arc<Upstream>,
        block_internal: bool,
    ) -> Result<Lease, String> {
        let gw = self
            .gateway
            .get_or_try_init(|| Gateway::bind(Arc::clone(&self.resolver)))
            .await
            .map_err(|e| format!("this node's egress gateway could not start: {e}"))?;
        gw.lease(op, proxy_id, upstream, block_internal)
    }

    /// Resolves once this node's settings no longer say direct: they name a proxy,
    /// usable or not. Work that started while the node sent directly waits on this, so
    /// that it stops rather than go on sending from the node's own address after the
    /// node was set to send through a proxy. Settings that are only stale do not end it.
    pub async fn until_not_direct(&self) {
        let mut rx = self.current.subscribe();
        // Checks the settings as they are now before it waits, so a switch made between
        // the work's start and this call is seen too.
        let _ = rx.wait_for(|n| !matches!(n.setting, Setting::Direct)).await;
    }

    /// This node's NATS connection dropped. A change the platform announces until it is
    /// back is lost, so from now until the settings are fetched again, ops ask for them
    /// before they run and .cfx jobs are refused.
    pub fn connection_lost(&self) {
        if self.platform_has_settings.load(Ordering::Relaxed) {
            self.mark_stale(Stale::Unsure);
        }
    }

    /// Keep the settings current without an announcement: fetch them every `every`,
    /// every [`RETRY_AFTER`] while the node knows it is behind, and at once each time
    /// `reconnected` is notified. Runs for as long as the daemon does. Only once the
    /// platform has shown it keeps settings for this node.
    pub async fn keep_current(
        self: Arc<Self>,
        http: reqwest::Client,
        api_url: String,
        api_key: String,
        reconnected: Arc<tokio::sync::Notify>,
        every: Duration,
    ) {
        let f = Fetch {
            http: &http,
            api_url: &api_url,
            api_key: &api_key,
        };
        let mut failing = false;
        loop {
            let wait = if self.stale().is_some() {
                RETRY_AFTER.min(every)
            } else {
                every
            };
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = reconnected.notified() => {}
            }
            if !self.platform_has_settings.load(Ordering::Relaxed) {
                continue;
            }
            match self.refresh(&f).await {
                Ok(_) => failing = false,
                // Said once, not on every retry, until a fetch works again.
                Err(e) if !failing => {
                    failing = true;
                    eprintln!("[egress] could not fetch this node's proxy settings: {e}");
                }
                Err(_) => {}
            }
        }
    }

    /// The heartbeat's `toolchain_status.egress`.
    pub fn heartbeat(&self) -> Value {
        let cur = self.current();
        let mut v = json!({
            "gateway": GATEWAY_VERSION,
            "rev": cur.rev,
            "mode": cur.mode(),
            "proxy_id": cur.proxy_id(),
        });
        if let Setting::Unusable(why) = &cur.setting {
            v["error"] = json!(why);
        }
        if self.stale().is_some() {
            v["stale"] = json!(true);
        }
        v
    }

    /// `{"mode","proxy_id"}` for a reply that says how something was sent.
    pub fn describe(lease: Option<&Lease>) -> Value {
        match lease {
            Some(l) => json!({"mode": "proxy", "proxy_id": l.proxy_id()}),
            None => json!({"mode": "direct", "proxy_id": null}),
        }
    }

    /// Whether anything this node sends must go through a proxy, or be refused: true
    /// unless the settings are direct and current.
    pub fn sends_through_proxy(&self) -> bool {
        !matches!(self.current().setting, Setting::Direct) || self.stale().is_some()
    }

    /// Run a node-side proxy check (`egress_test`): fetch `url` through the proxy and
    /// report the address the request arrived from. The platform names the proxy and
    /// hands it over for this check only, against the `test_id` it issued, also when it
    /// is the node's own: what is checked is what the platform holds now, never a copy
    /// the node kept. The answer is the body of `egress_test_result`.
    pub async fn check(&self, cmd: &Value, url: &str, f: &Fetch<'_>) -> Value {
        let Some(proxy_id) = cmd["proxy_id"].as_str().filter(|s| !s.is_empty()) else {
            return check_result(None, Err("the check names no proxy".into()));
        };
        let (id, upstream) = match fetch_candidate(f, proxy_id, cmd["test_id"].as_str()).await {
            Ok(c) => c,
            Err(e) => return check_result(Some(proxy_id), Err(e)),
        };
        let op = format!("check {}", cmd["command_id"].as_str().unwrap_or(""));
        let lease = match self.lease(&op, &id, upstream, false).await {
            Ok(l) => l,
            Err(e) => return check_result(Some(&id), Err(e)),
        };
        let started = Instant::now();
        let got = fetch_through(&lease, url).await;
        let latency = started.elapsed().as_millis() as u64;
        let got = got.map_err(|e| match lease.last_error() {
            Some(why) => format!("the proxy failed: {why}"),
            None => e,
        });
        check_result(Some(&id), got.map(|ip| (ip, latency)))
    }
}

fn check_result(proxy_id: Option<&str>, r: Result<(String, u64), String>) -> Value {
    match r {
        Ok((ip, ms)) => json!({
            "proxy_id": proxy_id, "ok": true, "exit_ip": ip, "latency_ms": ms, "error": null,
        }),
        Err(e) => json!({
            "proxy_id": proxy_id, "ok": false, "exit_ip": null, "latency_ms": null, "error": e,
        }),
    }
}

/// GET `url` through the lease and read the `ip=` line Cloudflare's trace answers with.
async fn fetch_through(lease: &Lease, url: &str) -> Result<String, String> {
    let proxy = reqwest::Proxy::all(lease.proxy_url())
        .map_err(|_| "the gateway's address could not be used".to_string())?;
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(CHECK_TIMEOUT)
        .build()
        .map_err(|e| format!("the check client could not be built: {e}"))?;
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("the check request failed: {}", e.without_url()))?;
    if !resp.status().is_success() {
        return Err(format!(
            "the check page answered HTTP {}",
            resp.status().as_u16()
        ));
    }
    let body = resp
        .text()
        .await
        .map_err(|e| format!("the check page could not be read: {}", e.without_url()))?;
    let ip = body
        .lines()
        .find_map(|l| l.strip_prefix("ip="))
        .map(str::trim)
        .ok_or("the check page did not say which address it saw")?;
    ip.parse::<std::net::IpAddr>()
        .map(|a| a.to_string())
        .map_err(|_| "the address the check page saw is not an IP address".into())
}

/// `POST /api/v1/node-egress`, authenticated by the node's key. The answer is the
/// platform's usual envelope, `{"status":200,"message":...,"data":{...}}`, and the
/// object returned is `data`.
async fn post_settings(f: &Fetch<'_>, mut body: Value) -> Result<Value, String> {
    body["api_key"] = json!(f.api_key);
    let url = format!("{}/api/v1/node-egress", f.api_url.trim_end_matches('/'));
    let resp = f
        .http
        .post(&url)
        .json(&body)
        .timeout(FETCH_TIMEOUT)
        .send()
        .await
        .map_err(|e| format!("the request failed: {}", e.without_url()))?;
    let code = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| format!("the answer could not be read: {}", e.without_url()))?;
    let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    let status = v["status"].as_i64();
    if !code.is_success() || status.is_some_and(|s| s != 200) {
        let msg = v["message"].as_str().unwrap_or("no message");
        return Err(format!(
            "the platform answered {} ({msg})",
            status.unwrap_or(code.as_u16() as i64)
        ));
    }
    match v.get("data") {
        Some(d) if d.is_object() => Ok(d.clone()),
        _ => Err("the platform's answer has no settings in it".into()),
    }
}

/// A proxy the platform hands this node for one check, against the `test_id` it issued
/// for it: `{"v":1,"proxy":{...}}`.
async fn fetch_candidate(
    f: &Fetch<'_>,
    proxy_id: &str,
    test_id: Option<&str>,
) -> Result<(String, Arc<Upstream>), String> {
    let data = post_settings(f, json!({"proxy_id": proxy_id, "test_id": test_id}))
        .await
        .map_err(|e| format!("could not fetch the proxy to check: {e}"))?;
    if data["v"].as_i64() != Some(SETTINGS_VERSION) {
        return Err("the proxy to check came in a version this node does not read".into());
    }
    let (id, up) =
        read_proxy(&data["proxy"]).map_err(|e| format!("the proxy cannot be used: {e}"))?;
    if id != proxy_id {
        return Err("the platform answered with a different proxy than the one to check".into());
    }
    Ok((id, Arc::new(up)))
}

/// The request line an engine gets: the op as before on a direct node, wrapped with the
/// lease's egress on a proxied one.
pub fn encode_for_engine(req: &Value, lease: Option<&Lease>) -> String {
    match lease {
        None => dguard::encode(req),
        Some(l) => dguard::encode(&dguard::wrap_egress(req, &l.wire())),
    }
}

/// What an engine's first answer to a wrapped request means for the op, when it means
/// the engine cannot run it: the note the op fails with. `None` for anything else, which
/// the op reads as it always has.
pub fn wrapper_refusal(engine: &str, first_line: &str) -> Option<String> {
    if !dguard::is_error(first_line) {
        return None;
    }
    let v: Value = serde_json::from_str(first_line).ok()?;
    let msg = v["message"].as_str().unwrap_or("");
    if msg.starts_with("Unknown operation: egress") || msg.starts_with("egress version") {
        return Some(format!(
            "{engine} on this node cannot send through a proxy. Run `crossfyre update`, then retry"
        ));
    }
    None
}

/// Whether the engine listening on `addr` sends a wrapped op through the proxy it names:
/// `Some(true)` for an engine that reads egress version 1, `Some(false)` for one that
/// does not (an engine older than the wrapper, or doorward, which reads the wrapper and
/// sends nothing through a proxy), and `None` when it did not answer.
pub async fn engine_reads_egress(addr: &str) -> Option<bool> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let probe = async {
        let s = tokio::net::TcpStream::connect(addr).await.ok()?;
        let (r, mut w) = s.into_split();
        let req = dguard::wrap_egress(
            &json!({"operation": "capabilities"}),
            &json!({"v": SETTINGS_VERSION, "proxy": null}),
        );
        let mut line = dguard::encode(&req);
        line.push('\n');
        w.write_all(line.as_bytes()).await.ok()?;
        BufReader::new(r).lines().next_line().await.ok().flatten()
    };
    let line = tokio::time::timeout(Duration::from_secs(2), probe)
        .await
        .ok()??;
    let v: Value = serde_json::from_str(&line).ok()?;
    if v["type"] == "capabilities" {
        return Some(v["egress"].as_i64() == Some(SETTINGS_VERSION));
    }
    dguard::is_error(&line).then_some(false)
}

/// How long an engine's answer to [`engine_reads_egress`] stands. An engine replaced
/// between two heartbeats (a package upgrade or downgrade, a restart by hand) is back on
/// the same port before the next one, so the heartbeat never sees it stopped; asking
/// again this often bounds how long it reports the previous engine's answer.
pub const ENGINE_ASK_EVERY: Duration = Duration::from_secs(30);

/// What each running engine answered when asked whether it reads the egress wrapper,
/// and when, by engine id. The heartbeat reports it per engine.
#[derive(Default)]
pub struct EngineEgress {
    answers: std::collections::HashMap<String, (bool, Instant)>,
}

impl EngineEgress {
    /// Whether `ext` is to be asked at `now`: it has not answered yet, or answered
    /// [`ENGINE_ASK_EVERY`] ago or longer.
    pub fn due(&self, ext: &str, now: Instant) -> bool {
        self.answers
            .get(ext)
            .is_none_or(|(_, at)| now.saturating_duration_since(*at) >= ENGINE_ASK_EVERY)
    }

    /// Keep an engine's answer, or forget the old one when it gave none.
    pub fn answered(&mut self, ext: String, reads: Option<bool>, now: Instant) {
        match reads {
            Some(r) => {
                self.answers.insert(ext, (r, now));
            }
            None => {
                self.answers.remove(&ext);
            }
        }
    }

    /// Whether `ext` said it reads the wrapper. An engine that has not said so does not.
    pub fn reads(&self, ext: &str) -> bool {
        self.answers.get(ext).is_some_and(|(r, _)| *r)
    }

    /// Forget `ext`'s answer: it was stopped, installed or restarted.
    pub fn remove(&mut self, ext: &str) {
        self.answers.remove(ext);
    }

    /// Forget every answer: the engines may all have been replaced.
    pub fn clear(&mut self) {
        self.answers.clear();
    }
}

#[cfg(test)]
mod tests;

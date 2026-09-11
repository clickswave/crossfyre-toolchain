//! The headless tier: run the application, and record what it actually asks for.
//!
//! Everything else in this crawler reads files the server hands over. That
//! reaches a great deal - `spa` recovers source maps, lazily-loaded chunks and
//! route tables without a browser - but it cannot reach two things, and they are
//! the two that matter most on a modern application:
//!
//!   * **A URL assembled from a value fetched at runtime.** `${base}/${tenant}/users`
//!     where `base` and `tenant` arrive in a config response. No amount of
//!     reading the bundle produces that string, because it does not exist until
//!     the application is running.
//!   * **The DOM the application builds.** A client-rendered page's links are not
//!     in the HTML the server sent; they are created by script after it loads.
//!
//! So this tier drives a real browser and records every request the page makes.
//!
//! # What it deliberately does not do
//!
//! It does not click anything.
//!
//! That is a safety decision, not a gap in the implementation. A crawler that
//! clicks whatever it finds will eventually click "Delete account", "Cancel
//! subscription" or "Send invitation", on somebody's live application, with a
//! session that is authorised to do it. Discovering one more endpoint is not
//! worth destroying a customer's data, and there is no reliable way to tell a
//! destructive control from a safe one by looking at it.
//!
//! Instead it NAVIGATES: to the seed, and to each client-side route that `spa`
//! recovered from the router config. That reaches the lazily-loaded sections of
//! an application - the admin area, the reports section - and records the API
//! calls each one makes on load, without ever pressing a button.
//!
//! # Why the browser is optional and stays optional
//!
//! A node without Chrome must keep working exactly as before. The tier is off
//! unless asked for, and when asked for on a machine with no browser it says so
//! and the crawl continues, because "the deep tier could not run" and "the deep
//! tier found nothing" are different results and a scan that confuses them is
//! lying about its coverage.

use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

/// How long to wait for the browser to say it is listening.
const LAUNCH_TIMEOUT: Duration = Duration::from_secs(20);
/// How long one navigation may take before it is abandoned.
pub const NAV_TIMEOUT: Duration = Duration::from_secs(20);
/// After load fires, how long to keep recording. An SPA's first data fetches
/// almost always land after the load event, so stopping there would miss the
/// very requests this tier exists to capture.
pub const SETTLE: Duration = Duration::from_secs(3);

/// Executables to try, in order, when the caller did not name one.
///
/// Chromium before Chrome deliberately: a machine with both is usually a
/// developer machine, and the packaged Chromium is the one that is safe to run
/// with a throwaway profile.
const CANDIDATES: &[&str] = &[
    "chromium",
    "chromium-browser",
    "google-chrome",
    "google-chrome-stable",
    "chrome",
    "msedge",
];

/// Find a browser to drive: `MACH_BROWSER` if set, else the first candidate on
/// PATH.
pub fn find_browser() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("MACH_BROWSER") {
        let p = PathBuf::from(p);
        return p.is_file().then_some(p);
    }
    let path = std::env::var_os("PATH")?;
    for name in CANDIDATES {
        for dir in std::env::split_paths(&path) {
            let c = dir.join(name);
            if c.is_file() {
                return Some(c);
            }
        }
    }
    None
}

/// The flags the browser is launched with.
///
/// Split out and tested because each one is here for a reason and a future edit
/// that drops the wrong one turns a crawl into a data leak or a sandbox escape.
pub fn launch_args(profile: &str, no_sandbox: bool) -> Vec<String> {
    let mut a: Vec<String> = vec![
        // Port 0: the OS picks, and the browser prints what it picked. A fixed
        // port races every other crawl on the machine.
        "--remote-debugging-port=0".into(),
        "--headless=new".into(),
        // A throwaway profile per run. Without this the browser reuses the
        // operator's real profile, with their cookies and their logged-in
        // sessions, and points them at the target.
        format!("--user-data-dir={profile}"),
        "--no-first-run".into(),
        "--no-default-browser-check".into(),
        // Everything below is the browser phoning home. A scanner that leaks the
        // target's hostnames to a telemetry endpoint is its own finding.
        "--disable-background-networking".into(),
        "--disable-sync".into(),
        "--disable-component-update".into(),
        "--disable-domain-reliability".into(),
        "--disable-client-side-phishing-detection".into(),
        "--safebrowsing-disable-auto-update".into(),
        "--metrics-recording-only".into(),
        "--disable-breakpad".into(),
        // Deterministic viewport, so a responsive app renders one way.
        "--window-size=1280,900".into(),
        "--disable-gpu".into(),
        "--hide-scrollbars".into(),
        "--mute-audio".into(),
    ];
    if no_sandbox {
        // Only when the caller asks. Containers frequently cannot give the
        // browser the namespaces it needs, and this is the documented way out,
        // but it removes the isolation between the page's renderer and the host.
        // It is a downgrade and is named as one.
        a.push("--no-sandbox".into());
    }
    a
}

/// The websocket endpoint out of the line Chrome prints on stderr.
pub fn parse_ws_url(line: &str) -> Option<String> {
    let i = line.find("ws://")?;
    Some(line[i..].trim().to_string())
}

/// A launched browser, its throwaway profile, and the endpoint to drive it.
pub struct Browser {
    child: Child,
    profile: PathBuf,
    pub ws_url: String,
}

impl Browser {
    pub async fn launch(exe: &PathBuf, no_sandbox: bool) -> Result<Self, String> {
        let profile = std::env::temp_dir().join(format!("mach-browser-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&profile).map_err(|e| format!("profile dir: {e}"))?;
        let args = launch_args(&profile.to_string_lossy(), no_sandbox);
        let mut child = Command::new(exe)
            .args(&args)
            .arg("about:blank")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| format!("could not start {}: {e}", exe.display()))?;

        let stderr = child.stderr.take().ok_or("no stderr from the browser")?;
        let mut lines = BufReader::new(stderr).lines();
        let deadline = tokio::time::Instant::now() + LAUNCH_TIMEOUT;
        let ws_url = loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                let _ = child.kill().await;
                let _ = std::fs::remove_dir_all(&profile);
                return Err("the browser never reported a debugging endpoint".into());
            }
            match tokio::time::timeout(remaining, lines.next_line()).await {
                Ok(Ok(Some(l))) => {
                    if let Some(u) = parse_ws_url(&l) {
                        break u;
                    }
                }
                // Stream ended, or an error: the browser died on startup.
                Ok(Ok(None)) | Ok(Err(_)) => {
                    let _ = child.kill().await;
                    let _ = std::fs::remove_dir_all(&profile);
                    return Err(
                        "the browser exited before it was ready. On a container this \
                                usually means it needs --no-sandbox; set MACH_BROWSER_NO_SANDBOX=1 \
                                to allow that, knowing it removes renderer isolation."
                            .into(),
                    );
                }
                Err(_) => continue,
            }
        };
        Ok(Browser {
            child,
            profile,
            ws_url,
        })
    }

    pub async fn shutdown(mut self) {
        let _ = self.child.kill().await;
        let _ = std::fs::remove_dir_all(&self.profile);
    }
}

impl Drop for Browser {
    fn drop(&mut self) {
        // kill_on_drop handles the process; the profile is ours to remove.
        let _ = std::fs::remove_dir_all(&self.profile);
    }
}

/// What one navigation produced.
#[derive(Debug, Default)]
pub struct Visit {
    /// Every request the page made, as (method, url). This is the point of the
    /// whole module.
    pub requests: Vec<(String, String)>,
    /// The DOM after script has built it.
    pub dom: String,
}

/// Is this a request worth recording?
///
/// Data and blob URLs are the page talking to itself, and the browser's own
/// extension scheme is not the application.
pub fn worth_recording(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

// ---------------------------------------------------------------------------
// The Chrome DevTools Protocol, as much of it as this needs
// ---------------------------------------------------------------------------

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

/// A DevTools connection: send commands, receive replies and events on one
/// socket, matched by id.
pub struct Cdp {
    ws: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    next_id: u64,
    /// Events that arrived while waiting for a command reply. Kept rather than
    /// dropped: the requests this tier exists to record arrive exactly while a
    /// navigation command is in flight, so discarding them would throw away the
    /// answer.
    pending: Vec<Value>,
}

impl Cdp {
    /// Connect to a DevTools endpoint on the loopback interface.
    ///
    /// A plain TCP stream rather than the crate's `connect_async`, for two
    /// reasons. It keeps TLS out of the dependency tree, which a localhost
    /// protocol has no use for. And it means the address is resolved HERE,
    /// where it can be refused: a DevTools endpoint is total control over a
    /// browser, and nothing should ever drive one across a network.
    pub async fn connect(ws_url: &str) -> Result<Self, String> {
        let addr = ws_authority(ws_url).ok_or("devtools: unparseable endpoint")?;
        let sock: std::net::SocketAddr = addr
            .parse()
            .map_err(|_| format!("devtools: {addr} is not a literal address"))?;
        if !sock.ip().is_loopback() {
            return Err(format!(
                "refusing to drive a browser at {sock}: a DevTools endpoint is total control over \
                 a browser and is only ever driven on loopback"
            ));
        }
        let stream = tokio::net::TcpStream::connect(sock)
            .await
            .map_err(|e| format!("devtools connect: {e}"))?;
        let (ws, _) = tokio_tungstenite::client_async(ws_url, stream)
            .await
            .map_err(|e| format!("devtools handshake: {e}"))?;
        Ok(Cdp {
            ws,
            next_id: 1,
            pending: Vec::new(),
        })
    }

    /// Send one command and wait for its reply, buffering any events that
    /// arrive first.
    pub async fn call(
        &mut self,
        method: &str,
        params: Value,
        session: Option<&str>,
        timeout: Duration,
    ) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        let mut msg = json!({"id": id, "method": method, "params": params});
        if let Some(s) = session {
            msg["sessionId"] = json!(s);
        }
        self.ws
            .send(Message::Text(msg.to_string()))
            .await
            .map_err(|e| format!("devtools send {method}: {e}"))?;

        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                return Err(format!("devtools {method}: no reply"));
            }
            let Ok(Some(Ok(m))) = tokio::time::timeout(left, self.ws.next()).await else {
                return Err(format!("devtools {method}: connection ended"));
            };
            let Message::Text(t) = m else { continue };
            let Ok(v) = serde_json::from_str::<Value>(&t) else {
                continue;
            };
            if v.get("id").and_then(|x| x.as_u64()) == Some(id) {
                if let Some(e) = v.get("error") {
                    return Err(format!("devtools {method}: {e}"));
                }
                return Ok(v.get("result").cloned().unwrap_or(json!({})));
            }
            if v.get("method").is_some() {
                self.pending.push(v);
            }
        }
    }

    /// Read events until `until` elapses, or until one of them is
    /// `Page.loadEventFired` and `settle` has passed since.
    ///
    /// Load is not the finish line: an SPA's first data fetches land after it,
    /// which is why there is a settle period rather than a stop.
    pub async fn pump(&mut self, until: Duration, settle: Duration) -> Vec<Value> {
        let mut out = std::mem::take(&mut self.pending);
        let hard = tokio::time::Instant::now() + until;
        let mut soft: Option<tokio::time::Instant> = out
            .iter()
            .any(|e| e.get("method").and_then(|m| m.as_str()) == Some("Page.loadEventFired"))
            .then(|| tokio::time::Instant::now() + settle);
        loop {
            let now = tokio::time::Instant::now();
            if now >= hard {
                break;
            }
            let left = match soft {
                Some(s) if s <= now => break,
                Some(s) => (s - now).min(hard - now),
                None => hard - now,
            };
            let Ok(Some(Ok(m))) = tokio::time::timeout(left, self.ws.next()).await else {
                // A timeout here is the normal quiet end of a page.
                if soft.is_some() {
                    break;
                }
                continue;
            };
            let Message::Text(t) = m else { continue };
            let Ok(v) = serde_json::from_str::<Value>(&t) else {
                continue;
            };
            if v.get("method").and_then(|x| x.as_str()) == Some("Page.loadEventFired") {
                soft = Some(tokio::time::Instant::now() + settle);
            }
            if v.get("method").is_some() {
                out.push(v);
            }
        }
        out
    }
}

/// `host:port` out of a `ws://host:port/path` endpoint.
pub fn ws_authority(ws_url: &str) -> Option<String> {
    let rest = ws_url.strip_prefix("ws://")?;
    let authority = rest.split('/').next()?;
    (!authority.is_empty()).then(|| authority.to_string())
}

/// Every (method, url) a batch of CDP events says the page requested.
pub fn requests_from(events: &[Value]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for e in events {
        if e.get("method").and_then(|m| m.as_str()) != Some("Network.requestWillBeSent") {
            continue;
        }
        let r = match e.pointer("/params/request") {
            Some(r) => r,
            None => continue,
        };
        let url = r.get("url").and_then(|u| u.as_str()).unwrap_or("");
        if !worth_recording(url) {
            continue;
        }
        let method = r
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or("GET")
            .to_uppercase();
        // A URL fragment is a client-side concern and never reaches the server.
        let url = url.split('#').next().unwrap_or(url).to_string();
        if !out.iter().any(|(m, u)| m == &method && u == &url) {
            out.push((method, url));
        }
    }
    out
}

/// Open a page, drive it to `url`, and record what it asks for.
///
/// A fresh target per navigation, deliberately: a single-page application that
/// keeps state between routes would otherwise skip the data fetches on the
/// second visit, and those fetches are the entire point.
pub async fn visit(cdp: &mut Cdp, url: &str) -> Result<Visit, String> {
    let t = cdp
        .call(
            "Target.createTarget",
            json!({"url": "about:blank"}),
            None,
            NAV_TIMEOUT,
        )
        .await?;
    let target_id = t
        .get("targetId")
        .and_then(|x| x.as_str())
        .ok_or("no targetId")?
        .to_string();

    let attach = cdp
        .call(
            "Target.attachToTarget",
            json!({"targetId": target_id, "flatten": true}),
            None,
            NAV_TIMEOUT,
        )
        .await?;
    let session = attach
        .get("sessionId")
        .and_then(|x| x.as_str())
        .ok_or("no sessionId")?
        .to_string();
    let s = Some(session.as_str());

    let _ = cdp.call("Network.enable", json!({}), s, NAV_TIMEOUT).await;
    let _ = cdp.call("Page.enable", json!({}), s, NAV_TIMEOUT).await;
    let nav = cdp
        .call("Page.navigate", json!({"url": url}), s, NAV_TIMEOUT)
        .await;

    let mut visit = Visit::default();
    if nav.is_ok() {
        let events = cdp.pump(NAV_TIMEOUT, SETTLE).await;
        visit.requests = requests_from(&events);
        if let Ok(r) = cdp
            .call(
                "Runtime.evaluate",
                json!({
                    "expression": "document.documentElement.outerHTML",
                    "returnByValue": true
                }),
                s,
                NAV_TIMEOUT,
            )
            .await
        {
            if let Some(v) = r.pointer("/result/value").and_then(|x| x.as_str()) {
                visit.dom = v.to_string();
            }
        }
    }

    let _ = cdp
        .call(
            "Target.closeTarget",
            json!({"targetId": target_id}),
            None,
            NAV_TIMEOUT,
        )
        .await;
    Ok(visit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_debugging_endpoint_is_read_off_the_startup_line() {
        let line = "DevTools listening on ws://127.0.0.1:41233/devtools/browser/9f2a-11ee";
        assert_eq!(
            parse_ws_url(line).as_deref(),
            Some("ws://127.0.0.1:41233/devtools/browser/9f2a-11ee")
        );
        assert_eq!(parse_ws_url("[0911/094500.1:INFO] starting"), None);
    }

    #[test]
    fn the_profile_is_never_the_operators_own() {
        let a = launch_args("/tmp/mach-browser-abc", false);
        assert!(
            a.iter()
                .any(|f| f == "--user-data-dir=/tmp/mach-browser-abc")
        );
        // Without this the browser opens the real profile, with the operator's
        // cookies, and points it at somebody else's application.
        assert!(a.iter().any(|f| f.starts_with("--user-data-dir=")));
    }

    #[test]
    fn the_browser_does_not_phone_home() {
        let a = launch_args("/tmp/p", false);
        for must in [
            "--disable-background-networking",
            "--disable-sync",
            "--disable-component-update",
            "--disable-domain-reliability",
            "--metrics-recording-only",
        ] {
            assert!(a.iter().any(|f| f == must), "missing {must}");
        }
    }

    #[test]
    fn the_sandbox_is_on_unless_it_is_asked_off() {
        assert!(
            !launch_args("/tmp/p", false)
                .iter()
                .any(|f| f == "--no-sandbox")
        );
        assert!(
            launch_args("/tmp/p", true)
                .iter()
                .any(|f| f == "--no-sandbox")
        );
    }

    #[test]
    fn the_port_is_chosen_by_the_os() {
        // A fixed port races every other crawl on the machine.
        assert!(
            launch_args("/tmp/p", false)
                .iter()
                .any(|f| f == "--remote-debugging-port=0")
        );
    }

    #[test]
    fn a_devtools_endpoint_is_only_ever_driven_on_loopback() {
        assert_eq!(
            ws_authority("ws://127.0.0.1:41233/devtools/browser/9f2a").as_deref(),
            Some("127.0.0.1:41233")
        );
        let remote: std::net::SocketAddr = "203.0.113.9:9222".parse().unwrap();
        assert!(!remote.ip().is_loopback(), "connect refuses this");
        let local: std::net::SocketAddr = "127.0.0.1:41233".parse().unwrap();
        assert!(local.ip().is_loopback());
    }

    #[test]
    fn requests_are_deduplicated_and_fragments_dropped() {
        let ev = vec![
            json!({"method":"Network.requestWillBeSent",
                   "params":{"request":{"url":"https://app.test/api/users","method":"GET"}}}),
            json!({"method":"Network.requestWillBeSent",
                   "params":{"request":{"url":"https://app.test/api/users#top","method":"get"}}}),
            json!({"method":"Network.requestWillBeSent",
                   "params":{"request":{"url":"data:image/png;base64,AA","method":"GET"}}}),
            json!({"method":"Network.requestWillBeSent",
                   "params":{"request":{"url":"https://app.test/api/orders","method":"POST"}}}),
            json!({"method":"Page.loadEventFired","params":{}}),
        ];
        let r = requests_from(&ev);
        assert_eq!(
            r,
            vec![
                ("GET".to_string(), "https://app.test/api/users".to_string()),
                (
                    "POST".to_string(),
                    "https://app.test/api/orders".to_string()
                ),
            ]
        );
    }

    #[test]
    fn only_real_http_requests_are_recorded() {
        assert!(worth_recording("https://app.test/api/users"));
        assert!(worth_recording("http://app.test/x"));
        assert!(!worth_recording("data:image/png;base64,AAAA"));
        assert!(!worth_recording("blob:https://app.test/9f2a"));
        assert!(!worth_recording("chrome-extension://abc/x.js"));
    }
}

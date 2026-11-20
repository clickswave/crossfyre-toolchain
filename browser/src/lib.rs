//! The headless tier of ambulo's crawler: run the application, and record what it
//! actually asks for.
//!
//! Everything else in that crawler reads files the server hands over. That
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
//! # Where it may go
//!
//! Only where the crawl may go. A browser follows a redirect wherever it points
//! and lets a page's script send it anywhere, so a target could otherwise steer
//! it onto a host the operator never listed, including the node's own network.
//! Every document request is held until the caller's gate answers for it, and
//! one the gate refuses is never sent. What the browser read is filed under the
//! page it ended on, not the address it was sent to.
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
///
/// 20s is right on a workstation: long enough for a cold start, short enough
/// that a browser which is never going to answer fails fast. It is marginal on
/// a loaded CI runner, where the same commit launched inside the budget on one
/// run and took longer than 20s on another running concurrently, which reads as
/// a detection regression rather than as a slow machine.
///
/// `AMBULO_BROWSER_LAUNCH_TIMEOUT_SECS` raises it where that is the known cost,
/// rather than making every user wait longer for a browser that is broken.
const LAUNCH_TIMEOUT_DEFAULT_SECS: u64 = 20;

fn launch_timeout() -> Duration {
    std::env::var("AMBULO_BROWSER_LAUNCH_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(LAUNCH_TIMEOUT_DEFAULT_SECS))
}
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

/// Find a browser to drive: `AMBULO_BROWSER` if set, else the first candidate on
/// PATH.
pub fn find_browser() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("AMBULO_BROWSER") {
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

/// How the browser is driven.
///
/// On Unix, a pipe on the browser's fds 3 and 4 that only this process holds. A
/// DevTools port, even one on loopback, can be attached to by any account on the
/// machine, and whoever attaches drives a browser that runs as the operator, local
/// files included.
#[cfg(unix)]
const DEBUGGING: &str = "--remote-debugging-pipe";
/// Elsewhere, a port. Port 0: the OS picks, and the browser prints what it picked.
/// A fixed port races every other crawl on the machine.
#[cfg(not(unix))]
const DEBUGGING: &str = "--remote-debugging-port=0";

/// The flags the browser is launched with.
///
/// Split out and tested because each one is here for a reason and a future edit
/// that drops the wrong one turns a crawl into a data leak or a sandbox escape.
pub fn launch_args(profile: &str, no_sandbox: bool) -> Vec<String> {
    let mut a: Vec<String> = vec![
        DEBUGGING.into(),
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

/// The preferences the throwaway profile starts with.
///
/// Network prediction off. With it on, the browser opens connections to a host
/// before it has decided to load anything there: to where a page's script is
/// about to navigate, or to a link it expects to be followed. The gate in
/// [`visit`] answers for every document request, but a preconnect is not a
/// request and never reaches it.
pub const PROFILE_PREFERENCES: &str = r#"{"net":{"network_prediction_options":2}}"#;

/// Create the throwaway profile with [`PROFILE_PREFERENCES`] in place.
fn write_profile(profile: &std::path::Path) -> std::io::Result<()> {
    let default = profile.join("Default");
    std::fs::create_dir_all(&default)?;
    std::fs::write(default.join("Preferences"), PROFILE_PREFERENCES)
}

/// The websocket endpoint out of the line Chrome prints on stderr.
#[cfg(not(unix))]
pub fn parse_ws_url(line: &str) -> Option<String> {
    let i = line.find("ws://")?;
    Some(line[i..].trim().to_string())
}

/// A launched browser and its throwaway profile.
pub struct Browser {
    child: Child,
    profile: PathBuf,
}

/// The note for a browser that died before it could be driven.
const EXITED_EARLY: &str = "the browser exited before it was ready. On a container this \
     usually means it needs --no-sandbox; set AMBULO_BROWSER_NO_SANDBOX=1 to allow that, \
     knowing it removes renderer isolation.";

impl Browser {
    /// Start a browser and connect to it.
    pub async fn launch(exe: &PathBuf, no_sandbox: bool) -> Result<(Self, Cdp), String> {
        let profile = std::env::temp_dir().join(format!("ambulo-browser-{}", uuid::Uuid::new_v4()));
        write_profile(&profile).map_err(|e| format!("profile dir: {e}"))?;
        let args = launch_args(&profile.to_string_lossy(), no_sandbox);
        let mut cmd = Command::new(exe);
        cmd.args(&args)
            .arg("about:blank")
            .stdout(Stdio::null())
            .kill_on_drop(true);
        match start(cmd, exe).await {
            Ok((child, cdp)) => Ok((Browser { child, profile }, cdp)),
            Err(e) => {
                // kill_on_drop has ended the process; the profile is ours to remove.
                let _ = std::fs::remove_dir_all(&profile);
                Err(e)
            }
        }
    }

    pub async fn shutdown(mut self) {
        let _ = self.child.kill().await;
        let _ = std::fs::remove_dir_all(&self.profile);
    }
}

/// Spawn the browser with a DevTools pipe and wait until it answers on it.
#[cfg(unix)]
async fn start(mut cmd: Command, exe: &std::path::Path) -> Result<(Child, Cdp), String> {
    use std::os::fd::{AsRawFd, OwnedFd};
    let pipe_err = |e: std::io::Error| format!("devtools pipe: {e}");
    // Both ends are close-on-exec, so nothing but the two the browser is given
    // below reaches it, or any other process this one starts.
    let (commands_r, commands_w) = std::io::pipe().map_err(pipe_err)?;
    let (replies_r, replies_w) = std::io::pipe().map_err(pipe_err)?;
    let (child_in, child_out) = (commands_r.as_raw_fd(), replies_w.as_raw_fd());
    cmd.stderr(Stdio::null());
    // SAFETY: only fcntl and dup2 run between fork and exec, and both are
    // async-signal-safe. The copies to 10 and up come first so that neither dup2
    // can overwrite the other's source; dup2 clears close-on-exec on 3 and 4.
    unsafe {
        cmd.pre_exec(move || {
            let a = libc::fcntl(child_in, libc::F_DUPFD_CLOEXEC, 10);
            let b = libc::fcntl(child_out, libc::F_DUPFD_CLOEXEC, 10);
            if a < 0 || b < 0 || libc::dup2(a, 3) < 0 || libc::dup2(b, 4) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("could not start {}: {e}", exe.display()))?;
    // The browser holds its own ends now. Closing ours is what makes its exit read
    // as the end of the pipe.
    drop(commands_r);
    drop(replies_w);
    let tx = tokio::net::unix::pipe::Sender::from_owned_fd(OwnedFd::from(commands_w))
        .map_err(pipe_err)?;
    let rx = tokio::net::unix::pipe::Receiver::from_owned_fd(OwnedFd::from(replies_r))
        .map_err(pipe_err)?;
    let mut cdp = Cdp::new(Wire::Pipe {
        tx,
        rx: BufReader::new(rx),
        partial: Vec::new(),
    });
    match cdp
        .call("Browser.getVersion", json!({}), None, launch_timeout())
        .await
    {
        Ok(_) => Ok((child, cdp)),
        Err(e) => {
            // A browser that died has closed the pipe, possibly a moment before
            // its exit can be collected.
            let exited = tokio::time::timeout(Duration::from_secs(2), child.wait())
                .await
                .is_ok();
            let _ = child.kill().await;
            if exited {
                Err(EXITED_EARLY.into())
            } else {
                Err(format!(
                    "the browser never answered on its DevTools pipe ({e})"
                ))
            }
        }
    }
}

/// Spawn the browser on a port the OS picks, read the endpoint off its stderr and
/// connect to it.
#[cfg(not(unix))]
async fn start(mut cmd: Command, exe: &std::path::Path) -> Result<(Child, Cdp), String> {
    let mut child = cmd
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not start {}: {e}", exe.display()))?;

    let stderr = child.stderr.take().ok_or("no stderr from the browser")?;
    let mut lines = BufReader::new(stderr).lines();
    let deadline = tokio::time::Instant::now() + launch_timeout();
    let ws_url = loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            let _ = child.kill().await;
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
                return Err(EXITED_EARLY.into());
            }
            Err(_) => continue,
        }
    };
    match Cdp::connect(&ws_url).await {
        Ok(cdp) => Ok((child, cdp)),
        Err(e) => {
            let _ = child.kill().await;
            Err(e)
        }
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
    /// Where the page ended up, which is not the address it was sent to when the
    /// server redirected it. The DOM's relative links mean this page, so they are
    /// resolved against this and not against the address asked for. `None` when
    /// the navigation failed or the address could not be read.
    pub final_url: Option<String>,
    /// Documents the gate refused to load: a redirect, a script navigation or a
    /// frame that would have taken the browser somewhere it may not go.
    pub refused: Vec<String>,
}

/// Decides whether the browser may load a document from a URL. Asked about the
/// page the visit starts on, every redirect hop after it, any navigation the
/// page's own script starts, and every frame.
pub type Gate = std::sync::Arc<dyn Fn(&str) -> bool + Send + Sync>;

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

#[cfg(not(unix))]
use futures_util::{SinkExt, StreamExt};
#[cfg(not(unix))]
use tokio_tungstenite::tungstenite::Message;

/// What a DevTools connection runs over.
enum Wire {
    /// A websocket to the port the browser picked.
    #[cfg(not(unix))]
    Socket(tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>),
    /// The browser's fds 3 and 4: one JSON message per NUL-terminated chunk.
    #[cfg(unix)]
    Pipe {
        tx: tokio::net::unix::pipe::Sender,
        rx: BufReader<tokio::net::unix::pipe::Receiver>,
        /// A message read in part when a wait timed out, kept for the next read.
        partial: Vec<u8>,
    },
}

impl Wire {
    async fn send(&mut self, text: String) -> Result<(), String> {
        match self {
            #[cfg(not(unix))]
            Wire::Socket(ws) => ws
                .send(Message::Text(text))
                .await
                .map_err(|e| e.to_string()),
            #[cfg(unix)]
            Wire::Pipe { tx, .. } => {
                use tokio::io::AsyncWriteExt;
                let mut bytes = text.into_bytes();
                bytes.push(0);
                tx.write_all(&bytes).await.map_err(|e| e.to_string())
            }
        }
    }

    /// The next text message, or `None` once the browser has gone. Safe to drop
    /// part way, as a timeout does: nothing read so far is lost.
    async fn recv(&mut self) -> Option<String> {
        match self {
            #[cfg(not(unix))]
            Wire::Socket(ws) => loop {
                match ws.next().await? {
                    Ok(Message::Text(t)) => return Some(t),
                    Ok(_) => continue,
                    Err(_) => return None,
                }
            },
            #[cfg(unix)]
            Wire::Pipe { rx, partial, .. } => loop {
                rx.read_until(0, partial).await.ok()?;
                if partial.pop() != Some(0) {
                    // End of the pipe, with or without half a message before it.
                    return None;
                }
                if let Ok(m) = String::from_utf8(std::mem::take(partial)) {
                    return Some(m);
                }
            },
        }
    }
}

/// A DevTools connection: send commands, receive replies and events on one
/// channel, matched by id.
pub struct Cdp {
    wire: Wire,
    next_id: u64,
    /// Events that arrived while waiting for a command reply. Kept rather than
    /// dropped: the requests this tier exists to record arrive exactly while a
    /// navigation command is in flight, so discarding them would throw away the
    /// answer.
    pending: Vec<Value>,
    /// While a visit runs, what decides each paused document request. A paused
    /// request waits for an answer, so it is answered the moment it is read,
    /// whichever wait reads it.
    gate: Option<Gate>,
    /// Documents the gate refused during the current visit.
    refused: Vec<String>,
}

impl Cdp {
    fn new(wire: Wire) -> Self {
        Cdp {
            wire,
            next_id: 1,
            pending: Vec::new(),
            gate: None,
            refused: Vec::new(),
        }
    }

    /// Answer a paused request if `v` is one: let it through or fail it, as the
    /// gate says. Returns whether `v` was a paused request.
    ///
    /// The answer is sent without waiting for its reply. Nothing is waiting on
    /// that id, so the reply is read and dropped like any other stray.
    async fn answer_paused(&mut self, v: &Value) -> bool {
        if v.get("method").and_then(|m| m.as_str()) != Some("Fetch.requestPaused") {
            return false;
        }
        let Some(request_id) = v.pointer("/params/requestId").and_then(|x| x.as_str()) else {
            return true;
        };
        let url = v
            .pointer("/params/request/url")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        // No gate means nothing was asked to be stopped.
        let allowed = self.gate.as_ref().is_none_or(|g| g(url));
        let (method, params) = if allowed {
            ("Fetch.continueRequest", json!({"requestId": request_id}))
        } else {
            self.refused
                .push(url.split('#').next().unwrap_or(url).to_string());
            (
                "Fetch.failRequest",
                json!({"requestId": request_id, "errorReason": "BlockedByClient"}),
            )
        };
        let id = self.next_id;
        self.next_id += 1;
        let mut msg = json!({"id": id, "method": method, "params": params});
        if let Some(s) = v.get("sessionId") {
            msg["sessionId"] = s.clone();
        }
        let _ = self.wire.send(msg.to_string()).await;
        true
    }

    /// Connect to a DevTools endpoint on the loopback interface.
    ///
    /// A plain TCP stream rather than the crate's `connect_async`, for two
    /// reasons. It keeps TLS out of the dependency tree, which a localhost
    /// protocol has no use for. And it means the address is resolved HERE,
    /// where it can be refused: a DevTools endpoint is total control over a
    /// browser, and nothing should ever drive one across a network.
    #[cfg(not(unix))]
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
        Ok(Cdp::new(Wire::Socket(ws)))
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
        self.wire
            .send(msg.to_string())
            .await
            .map_err(|e| format!("devtools send {method}: {e}"))?;

        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                return Err(format!("devtools {method}: no reply"));
            }
            let t = match tokio::time::timeout(left, self.wire.recv()).await {
                Ok(Some(t)) => t,
                Ok(None) => return Err(format!("devtools {method}: connection ended")),
                Err(_) => return Err(format!("devtools {method}: no reply")),
            };
            let Ok(v) = serde_json::from_str::<Value>(&t) else {
                continue;
            };
            if v.get("id").and_then(|x| x.as_u64()) == Some(id) {
                if let Some(e) = v.get("error") {
                    return Err(format!("devtools {method}: {e}"));
                }
                return Ok(v.get("result").cloned().unwrap_or(json!({})));
            }
            if self.answer_paused(&v).await {
                continue;
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
            let t = match tokio::time::timeout(left, self.wire.recv()).await {
                Ok(Some(t)) => t,
                // The browser has gone; nothing more is coming.
                Ok(None) => break,
                // A timeout here is the normal quiet end of a page.
                Err(_) if soft.is_some() => break,
                Err(_) => continue,
            };
            let Ok(v) = serde_json::from_str::<Value>(&t) else {
                continue;
            };
            if self.answer_paused(&v).await {
                continue;
            }
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
#[cfg(not(unix))]
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
///
/// Every document the page would load, `url` itself, each redirect hop and any
/// frame or script navigation, is held until `gate` answers for it, and one it
/// refuses is never requested. Requests for scripts, images and data are not
/// gated: they are what the page itself asks for, and they are recorded.
pub async fn visit(cdp: &mut Cdp, url: &str, gate: Gate) -> Result<Visit, String> {
    cdp.gate = Some(gate);
    cdp.refused.clear();
    let out = visit_gated(cdp, url).await;
    cdp.gate = None;
    let refused = std::mem::take(&mut cdp.refused);
    out.map(|mut v| {
        v.refused = refused;
        v
    })
}

async fn visit_gated(cdp: &mut Cdp, url: &str) -> Result<Visit, String> {
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
    // Hold every document request until the gate has answered for it. Without
    // this the browser follows a redirect wherever it points, as a browser does.
    let gated = cdp
        .call(
            "Fetch.enable",
            json!({"patterns": [{"urlPattern": "*", "resourceType": "Document", "requestStage": "Request"}]}),
            s,
            NAV_TIMEOUT,
        )
        .await;
    let nav = match gated {
        Ok(_) => {
            cdp.call("Page.navigate", json!({"url": url}), s, NAV_TIMEOUT)
                .await
        }
        Err(e) => Err(e),
    };

    let mut visit = Visit::default();
    // A navigation the gate refused fails with an error page, which is not the
    // application and has nothing to record.
    let failed = nav.as_ref().map_or(true, |r| {
        r.get("errorText").is_some_and(|e| e.as_str() != Some(""))
    });
    if !failed {
        let events = cdp.pump(NAV_TIMEOUT, SETTLE).await;
        visit.requests = requests_from(&events);
        if let Ok(r) = cdp
            .call(
                "Runtime.evaluate",
                json!({"expression": "location.href", "returnByValue": true}),
                s,
                NAV_TIMEOUT,
            )
            .await
        {
            visit.final_url = r
                .pointer("/result/value")
                .and_then(|x| x.as_str())
                .map(str::to_string);
        }
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

    #[cfg(not(unix))]
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
        let a = launch_args("/tmp/ambulo-browser-abc", false);
        assert!(
            a.iter()
                .any(|f| f == "--user-data-dir=/tmp/ambulo-browser-abc")
        );
        // Without this the browser opens the real profile, with the operator's
        // cookies, and points it at somebody else's application.
        assert!(a.iter().any(|f| f.starts_with("--user-data-dir=")));
    }

    #[test]
    fn the_profile_starts_with_network_prediction_off() {
        // 2 is "never". Without it the browser connects to where a page is
        // about to send it before the gate has been asked.
        let dir = std::env::temp_dir().join(format!("ambulo-prefs-{}", uuid::Uuid::new_v4()));
        write_profile(&dir).unwrap();
        let prefs: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.join("Default/Preferences")).unwrap(),
        )
        .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            prefs.pointer("/net/network_prediction_options"),
            Some(&json!(2))
        );
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

    #[cfg(not(unix))]
    #[test]
    fn the_port_is_chosen_by_the_os() {
        // A fixed port races every other crawl on the machine.
        assert!(
            launch_args("/tmp/p", false)
                .iter()
                .any(|f| f == "--remote-debugging-port=0")
        );
    }

    // A DevTools port on loopback is open to every local account, and whoever
    // attaches drives a browser running as the operator. On Unix the browser
    // talks over a pipe only this process holds.
    #[cfg(unix)]
    #[test]
    fn on_unix_the_browser_opens_no_debugging_port() {
        let a = launch_args("/tmp/p", false);
        assert!(
            !a.iter().any(|f| f.starts_with("--remote-debugging-port")),
            "{a:?}"
        );
        assert!(a.iter().any(|f| f == "--remote-debugging-pipe"), "{a:?}");
    }

    // Against a real browser when one is installed. Chrome writes the port it
    // listens on to DevToolsActivePort in the profile, so the file existing means a
    // port was opened.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_real_browser_is_driven_without_a_port() {
        let Some(exe) = find_browser() else {
            eprintln!("no browser on PATH; skipped");
            return;
        };
        let no_sandbox = std::env::var("AMBULO_BROWSER_NO_SANDBOX").is_ok();
        let (browser, mut cdp) = Browser::launch(&exe, no_sandbox).await.expect("launch");
        let v = visit(
            &mut cdp,
            "data:text/html,<a href=/x>x</a>",
            std::sync::Arc::new(|_: &str| true),
        )
        .await;
        let port_file = browser.profile.join("DevToolsActivePort");
        let opened_a_port = port_file.exists();
        browser.shutdown().await;
        let v = v.expect("visit");
        assert!(v.dom.contains("href=\"/x\""), "{}", v.dom);
        assert!(!opened_a_port, "the browser listened on a DevTools port");
    }

    // A browser that dies at once closes its end of the pipe, which has to read as
    // a failed start straight away rather than as a wait for the launch timeout.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_browser_that_exits_at_once_is_reported_without_waiting() {
        let exe = PathBuf::from("/usr/bin/false");
        if !exe.is_file() {
            return;
        }
        let started = tokio::time::Instant::now();
        let err = match Browser::launch(&exe, false).await {
            Ok(_) => panic!("a process that exits cannot be driven"),
            Err(e) => e,
        };
        assert!(err.contains("exited before it was ready"), "{err}");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "{:?}",
            started.elapsed()
        );
    }

    #[cfg(not(unix))]
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

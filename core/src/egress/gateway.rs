//! The node's egress gateway: a SOCKS5 server on loopback that every connection of a
//! proxied op passes through.
//!
//! An engine on a proxied node is never told which proxy carries its traffic. Each op
//! gets a [`Lease`] here instead: a user name and secret good for as long as the op
//! runs, handed to the engine as `socks5h://<handle>:<secret>@127.0.0.1:<port>`. The
//! team proxy, its credentials and how it was chosen stay with the node. Each
//! connection then:
//!
//! 1. authenticates as a live lease. An op that ended has dropped its lease, so its
//!    engine's later connections are refused, and the ones still open are cut;
//! 2. passes the lease's policy. With `block_internal` the destination is looked up on
//!    the node, only a public address goes on, and it goes on as an address;
//! 3. is opened onward through the lease's upstream with [`cfx_tunnel::connect`], and
//!    never directly. When the upstream fails, the engine gets a SOCKS failure.
//!
//! Everything a lease's connections did is counted, for the op's `operation_egress`.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use cfx_tunnel::socks5_server::{
    self, ADDRESS_TYPE_NOT_SUPPORTED, GENERAL_FAILURE, HOST_UNREACHABLE, NOT_ALLOWED, SUCCEEDED,
};
use cfx_tunnel::{Host, Kind, Target, Timeouts, Tunnel, TunnelError, Upstream};
use futures_util::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};

/// Connections the gateway holds at once, across every lease, counted from the moment
/// each is accepted. One more is closed before anything is read from it.
pub const MAX_CONNECTIONS: usize = 2048;

/// Descriptors the node keeps for everything but the gateway's tunnels: its connections
/// to the control plane, to NATS, and to the engine of each op it runs.
const RESERVED_FDS: u64 = 512;

/// The fewest connections the gateway is sized for, whatever the limit says.
const MIN_CONNECTIONS: usize = 16;

/// How many connections the gateway holds at once under a limit of `open_files`
/// descriptors: [`MAX_CONNECTIONS`], or fewer when the process may not open two for
/// each, the engine's side and the proxy's, and keep [`RESERVED_FDS`] besides. Over
/// the cap a connection is turned away at once, where past the descriptor limit it
/// would fail somewhere less clear, and so would whatever else the node was opening.
pub fn connection_cap(open_files: Option<u64>) -> usize {
    let Some(n) = open_files else {
        return MAX_CONNECTIONS;
    };
    let fit = n.saturating_sub(RESERVED_FDS) / 2;
    usize::try_from(fit)
        .unwrap_or(usize::MAX)
        .clamp(MIN_CONNECTIONS, MAX_CONNECTIONS)
}

/// Destinations listed one by one in a lease's summary. Connections to any further
/// destination are still counted in the totals.
pub const MAX_HOSTS: usize = 200;

/// How long an engine has to finish its SOCKS5 request.
const HANDSHAKE: Duration = Duration::from_secs(10);

/// A tunnel with no bytes either way for this long is closed.
const IDLE: Duration = Duration::from_secs(300);

/// How long the node waits for its resolver when it has to vet a destination name.
const RESOLVE: Duration = Duration::from_secs(10);

/// Looks a name up on the node. The gateway asks it only for a lease with
/// `block_internal`; tests hand in one with a fixed answer.
pub type Resolver =
    Arc<dyn Fn(String) -> BoxFuture<'static, io::Result<Vec<IpAddr>>> + Send + Sync>;

/// The system resolver, as every other lookup on the node uses.
pub fn system_resolver() -> Resolver {
    Arc::new(|name: String| {
        Box::pin(async move {
            let found = tokio::net::lookup_host((name.as_str(), 0)).await?;
            Ok(found.map(|a| a.ip()).collect())
        })
    })
}

pub struct Gateway {
    addr: SocketAddr,
    leases: Mutex<HashMap<String, Arc<LeaseState>>>,
    conns: Arc<Semaphore>,
    cap: usize,
    /// When the node last said the gateway was full, so a flood says it once a minute.
    full_said: Mutex<Option<Instant>>,
    resolver: Resolver,
    timeouts: Timeouts,
    idle: Duration,
}

impl fmt::Debug for Gateway {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gateway").field("addr", &self.addr).finish()
    }
}

impl Gateway {
    /// Listen on an ephemeral port on 127.0.0.1, sized to the descriptor limit in force.
    /// The gateway stops accepting once the last handle to it is dropped.
    pub async fn bind(resolver: Resolver) -> io::Result<Arc<Gateway>> {
        let cap = connection_cap(crate::os::open_file_limit());
        Gateway::bind_with(resolver, Timeouts::default(), IDLE, cap).await
    }

    pub(crate) async fn bind_with(
        resolver: Resolver,
        timeouts: Timeouts,
        idle: Duration,
        max_connections: usize,
    ) -> io::Result<Arc<Gateway>> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let gw = Arc::new(Gateway {
            addr: listener.local_addr()?,
            leases: Mutex::new(HashMap::new()),
            conns: Arc::new(Semaphore::new(max_connections)),
            cap: max_connections,
            full_said: Mutex::new(None),
            resolver,
            timeouts,
            idle,
        });
        let weak = Arc::downgrade(&gw);
        tokio::spawn(accept_loop(listener, weak));
        Ok(gw)
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// A lease for one op: connections presenting it go to `upstream`, under the
    /// policy `block_internal` names. It lasts until the [`Lease`] is dropped.
    pub fn lease(
        self: &Arc<Self>,
        op: &str,
        proxy_id: &str,
        upstream: Arc<Upstream>,
        block_internal: bool,
    ) -> Result<Lease, String> {
        let secret = random_hex(32)?;
        let mut leases = self
            .leases
            .lock()
            .map_err(|_| "the gateway's lease table broke")?;
        let handle = loop {
            let h = random_hex(8)?;
            if !leases.contains_key(&h) {
                break h;
            }
        };
        let (ended, _) = watch::channel(false);
        let state = Arc::new(LeaseState {
            op: op.to_string(),
            proxy_id: proxy_id.to_string(),
            secret,
            upstream,
            block_internal,
            // Where a check of each destination against the op's scope will go. Until
            // then a proxied op reaches what it would reach directly: recon contacts
            // third-party hosts on purpose, and the engines fence their own scope.
            scope: None,
            log: Mutex::new(EgressLog::default()),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            ended,
        });
        leases.insert(handle.clone(), Arc::clone(&state));
        Ok(Lease {
            gw: Arc::clone(self),
            handle,
            state,
            summary_taken: AtomicBool::new(false),
        })
    }

    fn find(&self, user: &str, pass: &str) -> Option<Arc<LeaseState>> {
        let lease = self.leases.lock().ok()?.get(user).cloned()?;
        socks5_server::secret_eq(pass.as_bytes(), lease.secret.as_bytes()).then_some(lease)
    }

    async fn serve(self: Arc<Self>, mut s: TcpStream) {
        // The cap counts a connection from the moment it is accepted, not once it has
        // authenticated: one that never sends a greeting would otherwise hold a
        // descriptor for the whole handshake deadline, outside the cap, and enough of
        // them leave the node unable to open anything else. Nothing is owed before the
        // greeting, so one over the cap is closed unanswered.
        let Ok(_permit) = Arc::clone(&self.conns).try_acquire_owned() else {
            self.say_full();
            return;
        };
        let _ = s.set_nodelay(true);
        let accepted = socks5_server::accept(&mut s, HANDSHAKE, |u, p| self.find(u, p)).await;
        // A missing lease or a wrong secret has been answered with an auth failure.
        let Ok((lease, target)) = accepted else {
            return;
        };
        let mut ended = lease.ended.subscribe();
        if *ended.borrow() {
            let _ = socks5_server::reply(&mut s, GENERAL_FAILURE).await;
            return;
        }
        let onward = match self.route(&lease, &target).await {
            Ok(t) => t,
            Err(Verdict::Refused(why)) => {
                lease.record(&target, Outcome::Refused, Some(why));
                let _ = socks5_server::reply(&mut s, NOT_ALLOWED).await;
                return;
            }
            Err(Verdict::Failed(code, why)) => {
                lease.record(&target, Outcome::Failed, Some(why));
                let _ = socks5_server::reply(&mut s, code).await;
                return;
            }
        };
        // Each vetted address in turn, while the proxy says it is that address it
        // cannot reach: a name with IPv4 and IPv6 addresses still opens through a proxy
        // that reaches only one kind, as it would for a client sending directly.
        let mut opened = None;
        for (i, t) in onward.iter().enumerate() {
            let r = tokio::select! {
                r = cfx_tunnel::connect(&lease.upstream, t, self.timeouts) => r,
                _ = until_ended(&mut ended) => {
                    let _ = socks5_server::reply(&mut s, GENERAL_FAILURE).await;
                    return;
                }
            };
            let next = i + 1 < onward.len() && r.as_ref().is_err_and(address_failed);
            opened = Some(r);
            if !next {
                break;
            }
        }
        let tunnel = match opened {
            Some(Ok(t)) => t,
            Some(Err(e)) => {
                lease.record(&target, Outcome::Failed, Some(&e.to_string()));
                let _ = socks5_server::reply(&mut s, e.reply_code()).await;
                return;
            }
            None => {
                lease.record(&target, Outcome::Failed, Some("no address to send it to"));
                let _ = socks5_server::reply(&mut s, HOST_UNREACHABLE).await;
                return;
            }
        };
        // The destination has its connection whatever the engine does next.
        lease.record(&target, Outcome::Ok, None);
        if socks5_server::reply(&mut s, SUCCEEDED).await.is_err() {
            return;
        }
        pump(
            s,
            tunnel,
            self.idle,
            ended,
            (&lease.bytes_up, &lease.bytes_down),
        )
        .await;
    }

    /// A line in the node's log when the gateway turns connections away, at most once a
    /// minute.
    fn say_full(&self) {
        let Ok(mut said) = self.full_said.lock() else {
            return;
        };
        if said.is_some_and(|at| at.elapsed() < Duration::from_secs(60)) {
            return;
        }
        *said = Some(Instant::now());
        eprintln!(
            "[egress] the gateway holds its limit of {} connections; new ones are closed \
             until some end",
            self.cap
        );
    }

    /// Where a connection goes on to, in the order to try, or why it does not.
    async fn route(&self, lease: &LeaseState, t: &Target) -> Result<Vec<Target>, Verdict> {
        if let Some(scope) = &lease.scope
            && !scope.admit(&host_text(&t.host), t.port, cfx_scope::Point::Connect, None)
        {
            return Err(Verdict::Refused(
                "the destination is outside the operation's scope",
            ));
        }
        if !lease.block_internal {
            // Sent on as the engine named it: a name goes to the proxy unresolved.
            return Ok(vec![t.clone()]);
        }
        let found = match &t.host {
            Host::Ip(ip) => vec![*ip],
            Host::Name(n) => {
                match tokio::time::timeout(RESOLVE, (self.resolver)(n.clone())).await {
                    Ok(Ok(a)) => a,
                    Ok(Err(_)) => {
                        return Err(Verdict::Failed(
                            HOST_UNREACHABLE,
                            "the name did not resolve",
                        ));
                    }
                    Err(_) => {
                        return Err(Verdict::Failed(
                            HOST_UNREACHABLE,
                            "the name did not resolve in time",
                        ));
                    }
                }
            }
        };
        let ips = vetted(&found, lease.upstream.kind == Kind::Socks4)?;
        Ok(ips
            .into_iter()
            .map(|ip| Target {
                host: Host::Ip(ip),
                port: t.port,
            })
            .collect())
    }
}

/// Resolves once the lease is dropped.
async fn until_ended(ended: &mut watch::Receiver<bool>) {
    // The guard `wait_for` returns is dropped here, before anything else is awaited.
    let _ = ended.wait_for(|e| *e).await;
}

async fn accept_loop(listener: TcpListener, gw: Weak<Gateway>) {
    loop {
        let s = match listener.accept().await {
            Ok((s, _)) => s,
            Err(_) => {
                // Out of descriptors, most likely. Give the open ones a moment to close.
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Some(gw) = gw.upgrade() else {
            return;
        };
        tokio::spawn(gw.serve(s));
    }
}

/// Why a `block_internal` connection was refused.
const PRIVATE: &str = "the destination is a private address, which this operation may not reach";

enum Verdict {
    /// The policy refused the destination, for this reason: SOCKS5 "not allowed".
    Refused(&'static str),
    /// The destination could not be vetted, or the proxy cannot carry it.
    Failed(u8, &'static str),
}

/// Addresses of one name a `block_internal` connection tries, at most this many.
const MAX_ADDRESSES: usize = 4;

/// The addresses a `block_internal` connection may go to, in the order to try them: the
/// public ones the name had, IPv4 first, since what counts is which kind the proxy can
/// reach and IPv4 is the kind nearly every proxy reaches. A SOCKS4 upstream, which
/// carries no IPv6, gets only the IPv4 ones.
fn vetted(found: &[IpAddr], v4_only: bool) -> Result<Vec<IpAddr>, Verdict> {
    let public: Vec<IpAddr> = found
        .iter()
        .copied()
        .filter(|ip| !cfx_tunnel::is_internal(ip))
        .collect();
    if public.is_empty() {
        return Err(Verdict::Refused(PRIVATE));
    }
    let v4 = public.iter().copied().filter(IpAddr::is_ipv4);
    let v6 = public.iter().copied().filter(IpAddr::is_ipv6);
    let order: Vec<IpAddr> = if v4_only {
        v4.collect()
    } else {
        v4.chain(v6).collect()
    };
    if order.is_empty() {
        return Err(Verdict::Failed(
            ADDRESS_TYPE_NOT_SUPPORTED,
            "the name has only IPv6 addresses, which a SOCKS4 proxy cannot carry",
        ));
    }
    Ok(order.into_iter().take(MAX_ADDRESSES).collect())
}

/// Whether the proxy failed this one address rather than the connection as a whole, so
/// another address of the same name may still open: it could not reach it, was
/// refused by it, or cannot carry its kind of address. A proxy that is down, refuses
/// the credentials or does not answer would fail every address the same way.
fn address_failed(e: &TunnelError) -> bool {
    matches!(
        e,
        TunnelError::Refused(0x03 | 0x04 | 0x05 | 0x08 | 0x5B) | TunnelError::Http(502..=504)
    )
}

fn host_text(h: &Host) -> String {
    match h {
        Host::Name(n) => n.clone(),
        Host::Ip(ip) => ip.to_string(),
    }
}

fn random_hex(bytes: usize) -> Result<String, String> {
    let mut b = vec![0u8; bytes];
    getrandom::fill(&mut b).map_err(|e| format!("no randomness for a gateway lease: {e}"))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// Copies both ways until both sides are done, the tunnel is idle for `idle`, or the
/// lease ends. The bytes sent toward the destination and back are added to `up` and
/// `down` as they pass, so a summary taken while the tunnel is still open has them.
async fn pump(
    mut client: TcpStream,
    tunnel: Tunnel,
    idle: Duration,
    mut ended: watch::Receiver<bool>,
    (up, down): (&AtomicU64, &AtomicU64),
) {
    let start = Instant::now();
    let last = AtomicU64::new(0);
    let (cr, cw) = client.split();
    let (tr, tw) = tokio::io::split(tunnel);
    let both = async {
        tokio::join!(
            copy_counting(cr, tw, up, &last, start),
            copy_counting(tr, cw, down, &last, start)
        )
    };
    let quiet = async {
        loop {
            let since = start
                .elapsed()
                .saturating_sub(Duration::from_millis(last.load(Ordering::Relaxed)));
            if since >= idle {
                return;
            }
            tokio::time::sleep(idle - since).await;
        }
    };
    tokio::select! {
        _ = both => {}
        _ = quiet => {}
        _ = until_ended(&mut ended) => {}
    }
}

async fn copy_counting<R, W>(
    mut r: R,
    mut w: W,
    count: &AtomicU64,
    last: &AtomicU64,
    start: Instant,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = match r.read(&mut buf).await {
            Ok(0) | Err(_) => {
                let _ = w.shutdown().await;
                return;
            }
            Ok(n) => n,
        };
        // Flushed every time: toward an HTTPS proxy the writer is a TLS stream, which
        // can keep the end of what it was given in its own buffer when the socket is
        // full, and nothing else would ever write that out.
        if w.write_all(&buf[..n]).await.is_err() || w.flush().await.is_err() {
            return;
        }
        count.fetch_add(n as u64, Ordering::Relaxed);
        last.store(start.elapsed().as_millis() as u64, Ordering::Relaxed);
    }
}

pub(crate) struct LeaseState {
    op: String,
    proxy_id: String,
    /// 64 hex digits, compared in constant time.
    secret: String,
    upstream: Arc<Upstream>,
    block_internal: bool,
    /// A scope every destination must be in, for scope enforcement on proxied nodes.
    /// Always `None` for now.
    scope: Option<Arc<cfx_scope::Guard>>,
    log: Mutex<EgressLog>,
    /// Bytes toward the destinations and back, across every tunnel, open ones included.
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
    /// `true` once the lease is dropped. Open tunnels watch it and close.
    ended: watch::Sender<bool>,
}

impl LeaseState {
    fn record(&self, t: &Target, outcome: Outcome, why: Option<&str>) {
        let Ok(mut log) = self.log.lock() else {
            return;
        };
        let first_failure = outcome == Outcome::Failed && log.failed == 0;
        log.record(host_text(&t.host), t.port, outcome);
        if let Some(why) = why {
            log.last_error = Some(why.to_string());
            // One line per op, so a dead proxy does not flood the node's log.
            if first_failure {
                eprintln!(
                    "[egress] op {}: {t} through {} failed: {why}",
                    self.op,
                    self.upstream.label()
                );
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Ok,
    Refused,
    Failed,
}

#[derive(Default)]
struct Counts {
    ok: u64,
    refused: u64,
    failed: u64,
}

/// What one lease's connections did.
#[derive(Default)]
struct EgressLog {
    /// Destinations in the order they were first asked for, up to [`MAX_HOSTS`].
    hosts: Vec<((String, u16), Counts)>,
    index: HashMap<(String, u16), usize>,
    /// Connections to a destination past the first [`MAX_HOSTS`].
    unlisted: u64,
    connections: u64,
    refused: u64,
    failed: u64,
    /// Why the latest refused or failed connection did not open. Never holds
    /// credentials: a tunnel error does not quote the proxy URL.
    last_error: Option<String>,
}

impl EgressLog {
    fn record(&mut self, host: String, port: u16, outcome: Outcome) {
        self.connections += 1;
        match outcome {
            Outcome::Ok => {}
            Outcome::Refused => self.refused += 1,
            Outcome::Failed => self.failed += 1,
        }
        let key = (host, port);
        let i = match self.index.get(&key) {
            Some(&i) => i,
            None if self.hosts.len() < MAX_HOSTS => {
                self.hosts.push((key.clone(), Counts::default()));
                self.index.insert(key, self.hosts.len() - 1);
                self.hosts.len() - 1
            }
            None => {
                self.unlisted += 1;
                return;
            }
        };
        let c = &mut self.hosts[i].1;
        match outcome {
            Outcome::Ok => c.ok += 1,
            Outcome::Refused => c.refused += 1,
            Outcome::Failed => c.failed += 1,
        }
    }
}

/// One op's permission to send through the gateway. Dropping it ends the permission:
/// new connections presenting it are refused and open ones are closed.
pub struct Lease {
    gw: Arc<Gateway>,
    handle: String,
    state: Arc<LeaseState>,
    summary_taken: AtomicBool,
}

impl fmt::Debug for Lease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Lease")
            .field("op", &self.state.op)
            .field("proxy_id", &self.state.proxy_id)
            .field("upstream", &self.state.upstream.label())
            .field("block_internal", &self.state.block_internal)
            .finish()
    }
}

impl Lease {
    /// The `egress` object of the engine wrapper: version 1 and this lease's URL.
    pub fn wire(&self) -> serde_json::Value {
        serde_json::json!({"v": 1, "proxy": self.proxy_url()})
    }

    /// `socks5h://<handle>:<secret>@127.0.0.1:<port>`, for an engine or one of the
    /// node's own clients. The `h` keeps a client from looking the name up itself.
    pub fn proxy_url(&self) -> String {
        format!(
            "socks5h://{}:{}@{}",
            self.handle, self.state.secret, self.gw.addr
        )
    }

    /// The platform's id for the proxy this lease sends through.
    pub fn proxy_id(&self) -> &str {
        &self.state.proxy_id
    }

    /// Why the latest connection that was refused or failed did not open, if one has.
    pub fn last_error(&self) -> Option<String> {
        self.state.log.lock().ok()?.last_error.clone()
    }

    /// The `egress` body of `operation_egress`.
    pub fn summary(&self) -> serde_json::Value {
        let Ok(log) = self.state.log.lock() else {
            return serde_json::json!({"mode": "proxy", "proxy_id": self.state.proxy_id});
        };
        let hosts: Vec<serde_json::Value> = log
            .hosts
            .iter()
            .map(|((host, port), c)| {
                serde_json::json!({
                    "host": host, "port": port,
                    "ok": c.ok, "refused": c.refused, "failed": c.failed,
                })
            })
            .collect();
        serde_json::json!({
            "mode": "proxy",
            "proxy_id": self.state.proxy_id,
            "connections": log.connections,
            "refused": log.refused,
            "failed": log.failed,
            "bytes_up": self.state.bytes_up.load(Ordering::Relaxed),
            "bytes_down": self.state.bytes_down.load(Ordering::Relaxed),
            "hosts_truncated": log.unlisted > 0,
            "hosts": hosts,
        })
    }

    /// [`summary`](Lease::summary) the first time it is asked for, then `None`, so the
    /// op's summary is published once whichever path ends it.
    pub fn take_summary(&self) -> Option<serde_json::Value> {
        (!self.summary_taken.swap(true, Ordering::SeqCst)).then(|| self.summary())
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        if let Ok(mut leases) = self.gw.leases.lock() {
            leases.remove(&self.handle);
        }
        self.state.ended.send_replace(true);
    }
}

#[cfg(test)]
mod tests;

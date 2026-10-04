//! Destinations the operator has asserted they are allowed to test.
//!
//! A scan's scope has always been one target, and `inject::in_scope` derives
//! everything from its hostname. That is the right default and it is why a
//! crawled `https://www.paypal.com/cgi-bin/webscr` form action stopped receiving
//! SQL injection payloads.
//!
//! It is also too narrow for anything that follows a finding somewhere. An SSRF
//! confirmed on the app reaches an internal service on another address by
//! definition, and refusing to look is refusing to report the thing that makes
//! the SSRF matter.
//!
//! So: an explicit list, and every word of that is load-bearing.
//!
//! * **Explicit.** The operator writes it down. Nothing a scan discovers is ever
//!   added to it, because "the scanner found an internal range" is not the same
//!   sentence as "you may attack this internal range", and conflating them is
//!   how a tool ends up probing somebody else's network.
//! * **A list.** Not a switch. "Allow internal addresses" would authorise every
//!   internal address, including the ones belonging to whoever shares the host.
//! * **Fail closed.** An entry that does not parse is refused, named, and
//!   dropped. It is never treated as a wildcard, and a malformed list is an
//!   empty list rather than a permissive one.
//!
//! Empty scope reproduces today's behaviour exactly, so every existing scan is
//! unaffected by this file existing.
//!
//! This started inside `cortex` and moved out when the workbench proxy needed it. The
//! proxy is where the stakes are highest: a scanner that probes out of scope sends some
//! requests somewhere it should not, while a proxy that carries out of scope records
//! somebody else's traffic and signs the operator's name to it. `Guard` below is the
//! half that was added for that, and it is what every egress point in the product calls.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

/// One thing the operator said they may test.
#[derive(Debug, Clone, PartialEq)]
pub enum Rule {
    /// A hostname, any port. `api.example.com`
    Host(String),
    /// A hostname on one port. `api.example.com:8443`
    HostPort(String, u16),
    /// Subdomains of a name. `*.example.com`
    ///
    /// Subdomains only. `*.example.com` does not admit `example.com`, because an
    /// authorisation list should mean exactly what it says and someone who wants
    /// the apex can write the apex. The alternative is a rule whose reach
    /// depends on which convention the reader has in mind.
    Suffix(String),
    /// An address range. `10.0.0.0/8`, `fd00::/8`
    Net(IpAddr, u8),
}

impl std::fmt::Display for Rule {
    /// The entry text a rule came from, so a list can be written back out exactly as it
    /// would have to be typed again. Round tripping matters: this is what gets saved with
    /// the project and shown in the window, and a rule that printed differently from the
    /// way it parses would quietly change meaning the next time it was loaded.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Rule::Host(h) => write!(f, "{h}"),
            Rule::HostPort(h, p) => write!(f, "{h}:{p}"),
            Rule::Suffix(b) => write!(f, "*.{b}"),
            Rule::Net(n, bits) => write!(f, "{n}/{bits}"),
        }
    }
}

/// A parsed authorisation list.
#[derive(Debug, Default, Clone)]
pub struct Scope {
    rules: Vec<Rule>,
}

/// Parse a list, returning what was understood and what was refused.
///
/// The refused entries are returned rather than dropped silently: a scan running
/// with two of an operator's five rules misunderstood is a scan whose results
/// mean something different from what they think it means.
pub fn parse(entries: &[String]) -> (Scope, Vec<String>) {
    let mut rules = Vec::new();
    let mut refused = Vec::new();
    for raw in entries {
        match parse_one(raw) {
            Some(r) => rules.push(r),
            None => refused.push(raw.clone()),
        }
    }
    (Scope { rules }, refused)
}

fn parse_one(raw: &str) -> Option<Rule> {
    let e = raw.trim().to_lowercase();
    if e.is_empty() || e.chars().any(|c| c.is_whitespace()) {
        return None;
    }
    // A scope entry is a destination, not a URL. Refusing these outright avoids
    // guessing what someone meant by `https://example.com/admin`.
    if e.contains("://") || e.contains('@') || e.contains('?') || e.contains('#') {
        return None;
    }

    if let Some((addr, bits)) = e.split_once('/') {
        let ip: IpAddr = addr.parse().ok()?;
        let bits: u8 = bits.parse().ok()?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        if bits > max {
            return None;
        }
        return Some(Rule::Net(ip, bits));
    }
    // Any other slash is a path, which a destination does not have.
    if e.contains('/') {
        return None;
    }

    if let Some(rest) = e.strip_prefix("*.") {
        // `*.com` is not an authorisation, it is an accident.
        if !rest.contains('.') || rest.starts_with('.') {
            return None;
        }
        return Some(Rule::Suffix(rest.to_string()));
    }
    if e.contains('*') {
        return None;
    }

    // A bare address, including IPv6 which is full of colons and must not be
    // mistaken for host:port.
    if let Ok(ip) = e.parse::<IpAddr>() {
        return Some(Rule::Host(ip.to_string()));
    }
    if let Some(inner) = e.strip_prefix('[') {
        // [::1] or [::1]:8080
        let (addr, rest) = inner.split_once(']')?;
        let ip: IpAddr = addr.parse().ok()?;
        return match rest {
            "" => Some(Rule::Host(ip.to_string())),
            _ => {
                let port: u16 = rest.strip_prefix(':')?.parse().ok()?;
                Some(Rule::HostPort(ip.to_string(), port))
            }
        };
    }
    if let Some((host, port)) = e.rsplit_once(':') {
        let port: u16 = port.parse().ok()?;
        if host.is_empty() {
            return None;
        }
        return Some(Rule::HostPort(host.to_string(), port));
    }
    if !e.contains('.') && e != "localhost" {
        // A single label that is not localhost is almost always a typo, and a
        // typo in an authorisation list should be loud.
        return None;
    }
    Some(Rule::Host(e))
}

impl Scope {
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Every rule as the text it parsed from.
    pub fn entries(&self) -> Vec<String> {
        self.rules.iter().map(|r| r.to_string()).collect()
    }

    /// Is this destination one the operator listed?
    ///
    /// `host` is the bare hostname or address with no port and no brackets;
    /// `port` is the URL's port, explicit or defaulted from its scheme.
    pub fn admits(&self, host: &str, port: Option<u16>) -> bool {
        let h = host
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_lowercase();
        if h.is_empty() {
            return false;
        }
        self.rules.iter().any(|r| match r {
            Rule::Host(name) => *name == h,
            Rule::HostPort(name, p) => *name == h && port == Some(*p),
            // The leading dot is what stops `*.example.com` admitting
            // `evil-example.com`, which is the whole reason suffix rules are
            // dangerous when written as a plain `ends_with`.
            Rule::Suffix(base) => h.len() > base.len() + 1 && h.ends_with(&format!(".{base}")),
            Rule::Net(net, bits) => h
                .parse::<IpAddr>()
                .map(|ip| in_net(&ip, net, *bits))
                .unwrap_or(false),
        })
    }
}

/// Containment, per family. A v4 address is never inside a v6 range and the
/// reverse, which matters because the two are trivially confusable once both
/// have been widened to integers.
fn in_net(ip: &IpAddr, net: &IpAddr, bits: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let (a, n) = (u32::from(*a), u32::from(*n));
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            a & mask == n & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let (a, n) = (u128::from(*a), u128::from(*n));
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits)
            };
            a & mask == n & mask
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// The guard
//
// `Scope` answers a question. `Guard` is the thing every egress point in the product
// actually holds: it carries the current policy, it can be retuned while a proxy is
// running, and it writes down what it refused.
//
// The recording is not a nicety. An authorisation boundary that silently drops traffic
// leaves an operator with a target that looks down, and leaves nobody able to answer the
// question the boundary exists for: months later, from the project file alone, did this
// tool ever touch something it should not have.
// ---------------------------------------------------------------------------

/// What the operator has said, as the three states that actually exist.
///
/// An empty `Scope` admits nothing, which is right for a scan and wrong as the default
/// for a proxy: a project that has never had a scope set must carry everything, or
/// turning this on bricks every project anybody already has.
///
/// Collapsing "unset" and "empty" into one is the trap. A list whose five entries all
/// failed to parse also produces an empty `Scope`, and if empty meant allow, one typo
/// would run an unrestricted proxy with the operator believing it was fenced.
#[derive(Debug, Clone, Default)]
pub enum Policy {
    /// Nothing was written down. Everything is carried, which is what every front end
    /// did before this existed.
    #[default]
    Unrestricted,
    /// Something was written down. Only what it admits is reached, and an entry that did
    /// not parse is absent from it rather than widening it.
    Restricted(Scope),
}

impl Policy {
    /// Blank entries are not a policy. A list that is all blanks gives `Unrestricted`;
    /// any non-blank entry gives `Restricted`, even when every one of them was refused,
    /// so a list of typos fails closed instead of becoming an open proxy.
    ///
    /// Returns the policy and the entries that were not understood, named rather than
    /// dropped.
    pub fn from_entries(entries: &[String]) -> (Self, Vec<String>) {
        let present: Vec<String> = entries
            .iter()
            .map(|e| e.trim().to_string())
            .filter(|e| !e.is_empty())
            .collect();
        if present.is_empty() {
            return (Policy::Unrestricted, Vec::new());
        }
        let (scope, rejected) = parse(&present);
        (Policy::Restricted(scope), rejected)
    }

    /// The port is known at every call site in the proxy: CONNECT defaults it to 443,
    /// absolute form to 80, and a flow always has one. So it is a `u16` here and not an
    /// `Option`, because a call site that dropped it would turn every `host:8443` rule
    /// into a refusal with nothing on screen to explain why.
    pub fn admits(&self, host: &str, port: u16) -> bool {
        match self {
            Policy::Unrestricted => true,
            Policy::Restricted(s) => s.admits(host, Some(port)),
        }
    }

    pub fn is_restricted(&self) -> bool {
        matches!(self, Policy::Restricted(_))
    }

    /// How many rules are in force. `None` when nothing was written down, which is a
    /// different thing from zero and has to read differently on screen.
    pub fn rules(&self) -> Option<usize> {
        match self {
            Policy::Unrestricted => None,
            Policy::Restricted(s) => Some(s.len()),
        }
    }

    pub fn entries(&self) -> Vec<String> {
        match self {
            Policy::Unrestricted => Vec::new(),
            Policy::Restricted(s) => s.entries(),
        }
    }
}

/// Where a destination was refused. Each is a different moment with a different cost of
/// getting it wrong, which is why they are named separately in the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Point {
    /// A CONNECT authority, before anything was dialled or any certificate minted.
    Connect,
    /// One request on the plaintext path, which has no CONNECT to be gated at.
    Request,
    /// A Repeater send, which egresses with no proxy running at all.
    Repeater,
}

impl Point {
    pub fn as_str(self) -> &'static str {
        match self {
            Point::Connect => "connect",
            Point::Request => "request",
            Point::Repeater => "repeater",
        }
    }

    /// Not `FromStr`: an unknown value is not an error worth a type, and the one caller
    /// is reading a column this crate wrote.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "connect" => Some(Point::Connect),
            "request" => Some(Point::Request),
            "repeater" => Some(Point::Repeater),
            _ => None,
        }
    }
}

/// One destination that was not reached.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Refusal {
    pub at_ms: i64,
    pub host: String,
    pub port: u16,
    pub point: Point,
    /// `GET /admin` for a request, or the name the client asked for when it differed
    /// from the destination. `None` when there is nothing to add.
    pub detail: Option<String>,
}

/// Somewhere durable a refusal is written.
///
/// Synchronous and infallible, for the same reason `ExchangeSink::record` is: this is
/// called from a path that cannot await and must not be able to fail the refusal.
pub trait RefusalSink: Send + Sync {
    fn refused(&self, r: &Refusal);
}

/// The live policy, shared by every egress point.
///
/// Behind locks rather than passed by value because the scope changes while a proxy is
/// running. An operator narrows a scope the moment they realise they are seeing traffic
/// they should not be, and making them stop and restart the proxy to do it means the
/// traffic keeps flowing while they work out how.
pub struct Guard {
    policy: RwLock<Policy>,
    sink: RwLock<Option<Arc<dyn RefusalSink>>>,
    recent: Mutex<VecDeque<Refusal>>,
    total: AtomicU64,
}

impl std::fmt::Debug for Guard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Guard")
            .field("policy", &self.policy.read().map(|p| p.rules()).ok())
            .field("refused", &self.total.load(Ordering::Relaxed))
            .finish()
    }
}

impl Guard {
    /// How many refusals are kept for the window to show. A ring, because this is a
    /// display convenience: the durable answer is the sink's.
    pub const RECENT_MAX: usize = 200;

    pub fn new(policy: Policy) -> Arc<Self> {
        Arc::new(Self {
            policy: RwLock::new(policy),
            sink: RwLock::new(None),
            recent: Mutex::new(VecDeque::new()),
            total: AtomicU64::new(0),
        })
    }

    pub fn unrestricted() -> Arc<Self> {
        Self::new(Policy::Unrestricted)
    }

    pub fn set_policy(&self, p: Policy) {
        if let Ok(mut w) = self.policy.write() {
            *w = p;
        }
    }

    pub fn policy(&self) -> Policy {
        self.policy.read().map(|p| p.clone()).unwrap_or_default()
    }

    pub fn is_restricted(&self) -> bool {
        self.policy
            .read()
            .map(|p| p.is_restricted())
            .unwrap_or(false)
    }

    /// `None` when nothing was written down.
    pub fn rules(&self) -> Option<usize> {
        self.policy.read().ok().and_then(|p| p.rules())
    }

    pub fn entries(&self) -> Vec<String> {
        self.policy.read().map(|p| p.entries()).unwrap_or_default()
    }

    pub fn set_sink(&self, sink: Option<Arc<dyn RefusalSink>>) {
        if let Ok(mut w) = self.sink.write() {
            *w = sink;
        }
    }

    /// The one call every egress point makes.
    ///
    /// `true` carries on. `false` means it was refused AND recorded, so no caller has to
    /// remember to report it: a boundary whose reporting is the caller's job is one that
    /// eventually has a caller that forgot.
    ///
    /// A poisoned lock refuses. The alternative is an unrestricted proxy following a
    /// panic somewhere else entirely, which is the one failure mode this must not have.
    pub fn admit(&self, host: &str, port: u16, point: Point, detail: Option<&str>) -> bool {
        let allowed = match self.policy.read() {
            Ok(p) => p.admits(host, port),
            Err(_) => false,
        };
        if allowed {
            return true;
        }
        let r = Refusal {
            at_ms: now_ms(),
            host: host.to_string(),
            port,
            point,
            detail: detail.map(|d| d.to_string()),
        };
        self.total.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut q) = self.recent.lock() {
            q.push_back(r.clone());
            while q.len() > Self::RECENT_MAX {
                q.pop_front();
            }
        }
        // Cloned out of the lock before calling, so a sink that blocks cannot hold the
        // guard shut against every other flow on the proxy.
        let sink = self.sink.read().ok().and_then(|s| s.clone());
        if let Some(s) = sink {
            s.refused(&r);
        }
        false
    }

    /// The newest first, which is the order somebody reads them in.
    pub fn recent(&self, limit: usize) -> Vec<Refusal> {
        self.recent
            .lock()
            .map(|q| q.iter().rev().take(limit).cloned().collect())
            .unwrap_or_default()
    }

    pub fn refused_total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// The one wording, so a refusal reads the same sentence wherever it surfaced: in a 403
/// body a browser renders, in the window, and in the log.
///
/// It names the destination and says what to do about it. "Forbidden" on its own sends
/// somebody looking for a bug in the target.
pub fn refusal_text(host: &str, port: u16) -> String {
    format!(
        "Out of scope: {host}:{port}\n\n         Crossfyre did not send this anywhere. The scope for this project does not list \n         this destination, so nothing was dialled and nothing was recorded against it.\n\n         Add it to the scope if you are authorised to test it."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(entries: &[&str]) -> Scope {
        parse(&entries.iter().map(|s| s.to_string()).collect::<Vec<_>>()).0
    }

    // ----- Policy: the three states, and why two of them must not be one -----

    #[test]
    fn nothing_written_down_admits_everything() {
        // A project that has never had a scope set must carry everything. If this
        // refused, turning the feature on would brick every project anybody already has
        // and the symptom would be a proxy that looks broken rather than one that is
        // fenced.
        let (p, rejected) = Policy::from_entries(&[]);
        assert!(!p.is_restricted());
        assert_eq!(p.rules(), None, "unset is not zero rules");
        assert!(p.admits("anything.example", 443));
        assert!(p.admits("10.0.0.1", 8080));
        assert!(rejected.is_empty());
    }

    #[test]
    fn blank_lines_are_not_a_policy() {
        // A textarea somebody pressed enter in twice is not an assertion about what they
        // may test.
        let (p, _) = Policy::from_entries(&["".into(), "   ".into(), "\t".into()]);
        assert!(!p.is_restricted());
        assert!(p.admits("anything.example", 443));
    }

    #[test]
    fn a_list_of_typos_refuses_everything_rather_than_allowing_it() {
        // THE one that matters. These five entries all fail to parse, so the Scope they
        // produce is empty, and an empty Scope is indistinguishable from an unset one if
        // the two states are collapsed. Collapsed the wrong way, one typo runs an
        // unrestricted proxy with the operator believing it is fenced.
        let bad = [
            "https://x".into(),
            "*.com".into(),
            "a b".into(),
            "::::".into(),
            "/8".into(),
        ];
        let (p, rejected) = Policy::from_entries(&bad);
        assert!(p.is_restricted(), "something was written down");
        assert_eq!(p.rules(), Some(0));
        assert!(!p.admits("x", 443));
        assert!(!p.admits("anything.example", 443));
        assert_eq!(rejected.len(), 5, "and every one is named: {rejected:?}");
    }

    #[test]
    fn a_partly_understood_list_keeps_what_parsed_and_names_the_rest() {
        let (p, rejected) = Policy::from_entries(&[
            "api.example.com".into(),
            "*.com".into(),
            "10.0.0.0/8".into(),
        ]);
        assert!(p.admits("api.example.com", 443));
        assert!(p.admits("10.1.2.3", 80));
        assert!(!p.admits("other.example.com", 443));
        assert_eq!(rejected, vec!["*.com".to_string()]);
    }

    #[test]
    fn a_port_rule_needs_the_port_and_the_port_is_never_dropped() {
        // `Scope::admits` takes an Option and never matches a HostPort rule against None.
        // Policy takes a u16 precisely so no call site can reach that arm by accident:
        // every one of them knows the port, and a dropped one would turn this rule into a
        // refusal with nothing on screen to explain it.
        let (p, _) = Policy::from_entries(&["api.example.com:8443".into()]);
        assert!(p.admits("api.example.com", 8443));
        assert!(!p.admits("api.example.com", 443));
    }

    #[test]
    fn entries_round_trip_through_their_text() {
        // What is shown is what is saved is what parses back. A rule that printed
        // differently from the way it reads would change meaning on the next load.
        let written = [
            "api.example.com".to_string(),
            "x.test:8443".into(),
            "*.example.com".into(),
            "10.0.0.0/8".into(),
        ];
        let (p, rejected) = Policy::from_entries(&written);
        assert!(rejected.is_empty());
        assert_eq!(p.entries(), written);
        let (again, _) = Policy::from_entries(&p.entries());
        assert_eq!(again.entries(), written);
    }

    // ----- Guard: refusing is also recording -----

    #[derive(Default)]
    struct Spy(Mutex<Vec<Refusal>>);
    impl RefusalSink for Spy {
        fn refused(&self, r: &Refusal) {
            self.0.lock().unwrap().push(r.clone());
        }
    }

    #[test]
    fn a_refusal_is_recorded_without_the_caller_doing_anything() {
        // The caller must not have to remember. A boundary whose reporting is the call
        // site's job is one that eventually has a call site that forgot, and the forgotten
        // one is invisible by construction.
        let g = Guard::new(Policy::from_entries(&["in.example".into()]).0);
        let spy = Arc::new(Spy::default());
        g.set_sink(Some(spy.clone()));

        assert!(g.admit("in.example", 443, Point::Connect, None));
        assert!(!g.admit("out.example", 8080, Point::Request, Some("GET /admin")));

        let seen = spy.0.lock().unwrap().clone();
        assert_eq!(seen.len(), 1, "the admitted one is not a refusal");
        assert_eq!(seen[0].host, "out.example");
        assert_eq!(seen[0].port, 8080);
        assert_eq!(seen[0].point, Point::Request);
        assert_eq!(seen[0].detail.as_deref(), Some("GET /admin"));
        assert_eq!(g.refused_total(), 1);
        assert_eq!(g.recent(10).len(), 1);
    }

    #[test]
    fn the_scope_can_be_narrowed_while_traffic_is_flowing() {
        // Without this the operator has to stop the proxy to fence it, and the traffic
        // they are trying to stop keeps flowing while they work out how.
        let g = Guard::unrestricted();
        assert!(g.admit("anywhere.example", 443, Point::Connect, None));
        g.set_policy(Policy::from_entries(&["in.example".into()]).0);
        assert!(!g.admit("anywhere.example", 443, Point::Connect, None));
        assert!(g.admit("in.example", 443, Point::Connect, None));
    }

    #[test]
    fn the_recent_ring_is_bounded_and_newest_first() {
        let g = Guard::new(Policy::from_entries(&["in.example".into()]).0);
        for i in 0..(Guard::RECENT_MAX + 50) {
            g.admit(&format!("h{i}.example"), 443, Point::Connect, None);
        }
        assert_eq!(g.refused_total() as usize, Guard::RECENT_MAX + 50);
        let recent = g.recent(1000);
        assert_eq!(recent.len(), Guard::RECENT_MAX, "a display ring, not a log");
        assert_eq!(
            recent[0].host,
            format!("h{}.example", Guard::RECENT_MAX + 49)
        );
    }

    #[test]
    fn a_poisoned_guard_refuses_rather_than_opening() {
        // A panic somewhere else in the process must not turn this into an open proxy.
        // It is the one failure direction that cannot be allowed: everything else here
        // fails loudly, and this one would fail by quietly carrying traffic.
        let g = Guard::new(Policy::from_entries(&["in.example".into()]).0);
        let g2 = g.clone();
        let _ = std::thread::spawn(move || {
            let _w = g2.policy.write().unwrap();
            panic!("something else went wrong");
        })
        .join();
        assert!(g.policy.is_poisoned(), "the lock really is poisoned");
        assert!(
            !g.admit("in.example", 443, Point::Connect, None),
            "a destination that WOULD be in scope is refused, because the policy can no \
             longer be read and the safe answer to that is no"
        );
        assert_eq!(g.refused_total(), 1, "and it is still recorded");
    }

    #[test]
    fn the_refusal_text_names_the_destination_and_says_nothing_was_sent() {
        // What a browser renders. "Forbidden" on its own sends somebody looking for a bug
        // in the target.
        let t = refusal_text("out.example", 8443);
        assert!(t.contains("out.example:8443"));
        assert!(t.to_lowercase().contains("did not send"));
        assert!(t.to_lowercase().contains("scope"));
    }

    #[test]
    fn an_empty_list_admits_nothing() {
        let s = scope(&[]);
        assert!(s.is_empty());
        assert!(!s.admits("example.com", Some(443)));
        assert!(!s.admits("10.0.0.1", None));
    }

    #[test]
    fn a_wildcard_matches_on_a_dot_and_not_on_a_prefix() {
        let s = scope(&["*.example.com"]);
        assert!(s.admits("api.example.com", Some(443)));
        assert!(s.admits("a.b.example.com", None));
        // The one that matters: a plain ends_with would admit this.
        assert!(!s.admits("evil-example.com", Some(443)));
        assert!(!s.admits("exampleXcom", None));
        // Subdomains only, as documented.
        assert!(!s.admits("example.com", Some(443)));
    }

    #[test]
    fn a_port_rule_needs_the_port() {
        let s = scope(&["api.example.com:8443"]);
        assert!(s.admits("api.example.com", Some(8443)));
        assert!(!s.admits("api.example.com", Some(443)));
        assert!(!s.admits("api.example.com", None));
    }

    #[test]
    fn a_host_rule_ignores_the_port() {
        let s = scope(&["api.example.com"]);
        assert!(s.admits("api.example.com", Some(443)));
        assert!(s.admits("api.example.com", Some(9999)));
        assert!(s.admits("api.example.com", None));
    }

    #[test]
    fn ranges_contain_what_they_should_and_nothing_else() {
        let s = scope(&["10.0.0.0/8", "192.168.1.0/24"]);
        assert!(s.admits("10.255.3.4", None));
        assert!(s.admits("192.168.1.7", Some(6379)));
        assert!(!s.admits("192.168.2.7", None));
        assert!(!s.admits("11.0.0.1", None));
        // A name that is not an address is not in a range.
        assert!(!s.admits("ten.example.com", None));
    }

    #[test]
    fn families_do_not_cross() {
        let s = scope(&["::/0"]);
        // Everything in v6, nothing in v4, even though /0 is "all" in its family.
        assert!(s.admits("fd00::1", None));
        assert!(!s.admits("10.0.0.1", None));
    }

    #[test]
    fn nonsense_is_refused_rather_than_widened() {
        let (s, refused) = parse(
            &[
                "https://example.com", // a URL
                "example.com/admin",   // a path
                "*",                   // everything
                "*.com",               // a TLD
                "10.0.0.0/99",         // impossible prefix
                "not a host",          // whitespace
                "",                    // empty
                "localhost:notaport",  // bad port
                "admin",               // bare label, almost certainly a typo
            ]
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>(),
        );
        assert!(s.is_empty(), "nothing in that list is an authorisation");
        assert_eq!(refused.len(), 9, "and every one of them is reported");
    }

    #[test]
    fn the_forms_an_operator_actually_writes_all_parse() {
        let (s, refused) = parse(
            &[
                "example.com",
                "*.example.com",
                "10.0.0.0/8",
                "localhost",
                "127.0.0.1:6379",
                "[::1]",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>(),
        );
        assert!(refused.is_empty(), "refused: {refused:?}");
        assert_eq!(s.len(), 6);
        assert!(s.admits("127.0.0.1", Some(6379)));
        assert!(s.admits("::1", None));
        assert!(s.admits("localhost", Some(3000)));
    }

    #[test]
    fn entries_are_case_insensitive_and_trimmed() {
        let s = scope(&["  API.Example.COM  "]);
        assert!(s.admits("api.example.com", None));
    }
}

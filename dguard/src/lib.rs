//! Inbound listener policy for the engine daemons.
//!
//! The daemons speak newline-delimited JSON over raw TCP. There is no session,
//! no handshake and no per-connection state, so **the bind address is the
//! security boundary**. They used to bind `0.0.0.0`, which put an unauthenticated
//! command channel on every interface: anyone who could reach the port could
//! drive a scan, and `ambulo`'s wordlist parameter is a filesystem path, so they
//! could also read files off the host one line at a time.
//!
//! Loopback is now the default. That costs nothing in the normal deployment,
//! because the node dials `127.0.0.1` (`toolchain::config::engine_addr`) whether
//! or not the daemon is listening more widely.
//!
//! Two escape hatches exist for operators who genuinely split the node and the
//! engines across hosts, and they are deliberately awkward:
//!
//! * [`BIND_ENV`] moves the listener off loopback.
//! * [`TOKEN_ENV`] sets a shared secret that clients must present.
//!
//! Binding off loopback without a token is permitted (an operator may have put
//! the port behind a firewall or a private network) but it is announced on every
//! start, because it is the configuration that used to be the silent default.
//!
//! It is also where an engine's client starts the engine's daemon when none runs
//! ([`Daemon`]), and where a daemon started that way exits once nothing uses it
//! ([`exit_when_idle`]).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

mod db;
mod idle;
mod lines;
pub mod ports;
mod start;
mod words;

pub use db::{DbAction, PurgeArgs, answer, ask, list_scans, resume_request, run_db};
pub use idle::{IDLE_EXIT_ENV, exit_when_idle, spawn_busy};
pub use lines::{Lines, MAX_LINE};
pub use start::{Daemon, LOG_LIMIT, NO_AUTOSTART_ENV, daemon_args, not_running, unit_name};
pub use words::{CHUNK_WORDS, WORDS_FOLLOW, WordChunks, list_name, send_words};

/// Moves a daemon listener off loopback. Value is an IP, not a host name.
pub const BIND_ENV: &str = "CFX_DAEMON_BIND";

/// Shared secret required in each request envelope when set.
pub const TOKEN_ENV: &str = "CFX_DAEMON_TOKEN";

/// Bind address for a daemon on `port`.
///
/// Defaults to loopback. [`BIND_ENV`] overrides the host, and a value that does
/// not parse as an IP address falls back to loopback rather than widening the
/// listener: a typo in an operator's env must not be the thing that exposes the
/// command channel.
pub fn bind_addr(port: u16) -> SocketAddr {
    let raw = std::env::var(BIND_ENV).ok();
    let addr = bind_addr_from(raw.as_deref(), port);
    if let Some(r) = raw.as_deref() {
        if addr.ip().is_loopback() && !r.trim().is_empty() && r.trim().parse::<IpAddr>().is_err() {
            eprintln!("warning: {BIND_ENV}={r:?} is not an IP address; binding loopback instead");
        }
    }
    addr
}

/// The bind decision, without touching the environment.
///
/// Split out so the policy is unit-testable: env vars are process-global and
/// tests run in parallel, so asserting on them directly is a race.
pub fn bind_addr_from(raw: Option<&str>, port: u16) -> SocketAddr {
    let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        Some(r) => r
            .parse::<IpAddr>()
            .map(|ip| SocketAddr::new(ip, port))
            .unwrap_or(loopback),
        None => loopback,
    }
}

/// The shared-secret check applied to each request envelope.
#[derive(Clone, Debug, Default)]
pub struct Gate {
    secret: Option<String>,
}

impl Gate {
    /// Reads [`TOKEN_ENV`]. An unset, blank or whitespace-only value disables the
    /// check, matching the treatment of empty secrets elsewhere in the platform:
    /// a blank secret must never be a secret that everything matches.
    pub fn from_env() -> Self {
        let secret = std::env::var(TOKEN_ENV)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        Self { secret }
    }

    /// Whether a token is required at all.
    pub fn enabled(&self) -> bool {
        self.secret.is_some()
    }

    /// Whether `token` satisfies the gate.
    ///
    /// Comparison is constant-time in the length-matched case so a caller cannot
    /// recover the secret byte by byte from response timing.
    pub fn allows(&self, token: Option<&str>) -> bool {
        let Some(expected) = self.secret.as_deref() else {
            return true;
        };
        let Some(given) = token else {
            return false;
        };
        ct_eq(expected.as_bytes(), given.as_bytes())
    }

    /// The reply that ends a connection at `line`, or `None` when the line may go
    /// on to the daemon's request parser.
    ///
    /// Every client of these daemons writes one JSON object per line, so a line
    /// that is not one did not come from a client. The case that matters is HTTP:
    /// a web page open in the operator's browser can POST to a loopback port, and
    /// the browser writes a request line and headers ahead of the body the page
    /// chose. Answering each of those lines and reading on reaches the body and
    /// runs it as a request. Closing at the first one never reads that far, and
    /// no request line or header can parse as a JSON object.
    pub fn refusal(&self, line: &str) -> Option<&'static str> {
        let Ok(serde_json::Value::Object(req)) = serde_json::from_str(line) else {
            return Some(NOT_A_REQUEST);
        };
        if self.allows(req.get("token").and_then(|t| t.as_str())) {
            None
        } else {
            Some(UNAUTHORIZED)
        }
    }

    /// Prints the listener's posture once at start.
    ///
    /// Worth the line on stdout: "unauthenticated on every interface" was the old
    /// default and left no trace, so the configuration that reproduces it should
    /// be the one that is hardest to run without noticing.
    pub fn announce(&self, service: &str, addr: SocketAddr) {
        let public = !addr.ip().is_loopback();
        match (public, self.enabled()) {
            (true, false) => eprintln!(
                "warning: {service} daemon is listening on {addr}, which is not \
                 loopback, and {TOKEN_ENV} is unset. Any host that can reach this \
                 port can drive this engine. Set {TOKEN_ENV} or bind loopback."
            ),
            (true, true) => {
                println!("{service} daemon listening on {addr} (token required)")
            }
            (false, true) => {
                println!("{service} daemon listening on {addr} (token required)")
            }
            (false, false) => println!("{service} daemon listening on {addr}"),
        }
    }
}

/// Sent before closing on a line that is not a JSON object. It carries both
/// `type` and `status` so a client that reads either sees an error.
const NOT_A_REQUEST: &str =
    "{\"type\":\"error\",\"status\":\"error\",\"message\":\"not a JSON request\"}\n";

/// Sent before closing on a request without the configured token, in the same
/// `type`/`message` envelope as every other reply: a client that breaks on
/// `type == "error"` has to recognise it, or it waits for a line that never comes.
const UNAUTHORIZED: &str = "{\"type\":\"error\",\"message\":\"unauthorized\"}\n";

/// Length-checked constant-time byte comparison.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_loopback() {
        assert!(bind_addr_from(None, 4441).ip().is_loopback());
        assert!(bind_addr_from(Some(""), 4441).ip().is_loopback());
        assert!(bind_addr_from(Some("  "), 4441).ip().is_loopback());
    }

    #[test]
    fn a_malformed_bind_does_not_widen_the_listener() {
        assert!(bind_addr_from(Some("not-an-ip"), 4441).ip().is_loopback());
        assert!(bind_addr_from(Some("0.0.0.0.0"), 4441).ip().is_loopback());
    }

    #[test]
    fn an_explicit_address_is_honoured() {
        let a = bind_addr_from(Some("0.0.0.0"), 4441);
        assert!(!a.ip().is_loopback());
        assert_eq!(a.port(), 4441);
    }

    #[test]
    fn an_unset_token_allows_everything() {
        let g = Gate { secret: None };
        assert!(g.allows(None));
        assert!(g.allows(Some("anything")));
        assert!(!g.enabled());
    }

    #[test]
    fn a_set_token_rejects_absent_and_wrong_values() {
        let g = Gate {
            secret: Some("sekrit".into()),
        };
        assert!(g.allows(Some("sekrit")));
        assert!(!g.allows(None));
        assert!(!g.allows(Some("")));
        assert!(!g.allows(Some("sekri")));
        assert!(!g.allows(Some("sekrit ")));
        assert!(g.enabled());
    }

    #[test]
    fn a_line_that_is_not_a_json_object_is_refused() {
        let open = Gate { secret: None };
        for line in [
            "POST / HTTP/1.1",
            "Host: 127.0.0.1:4441",
            "Content-Type: text/plain;charset=UTF-8",
            "GET /?{\"operation\":\"scan\"} HTTP/1.1",
            "[{\"operation\":\"scan\"}]",
            "\"scan\"",
            "1",
            "{\"operation\":",
        ] {
            assert_eq!(open.refusal(line), Some(NOT_A_REQUEST), "{line}");
        }
        assert_eq!(open.refusal("{\"operation\":\"scan\"}"), None);
        // A JSON object that is not a valid request still reaches the parser,
        // which answers it and keeps the connection, as before.
        assert_eq!(open.refusal("{}"), None);
    }

    #[test]
    fn the_token_is_checked_after_the_shape() {
        let g = Gate {
            secret: Some("sekrit".into()),
        };
        assert_eq!(g.refusal("POST / HTTP/1.1"), Some(NOT_A_REQUEST));
        assert_eq!(g.refusal("{\"operation\":\"scan\"}"), Some(UNAUTHORIZED));
        assert_eq!(
            g.refusal("{\"operation\":\"scan\",\"token\":\"sekrit\"}"),
            None
        );
    }

    #[test]
    fn ct_eq_matches_normal_equality() {
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}

/// Serialises a daemon request envelope, stamping in the configured token.
///
/// Callers build their request as a `json!` object and hand it here instead of
/// calling `serde_json::to_string` directly, so that a deployment which sets
/// [`TOKEN_ENV`] authenticates every call site at once. With no token set this
/// is exactly `to_string`, which is why turning the gate on is a deployment
/// decision rather than a code change.
pub fn encode(req: &serde_json::Value) -> String {
    encode_with(req, std::env::var(TOKEN_ENV).ok().as_deref())
}

/// The stamping decision, without touching the environment. See [`bind_addr_from`].
pub fn encode_with(req: &serde_json::Value, token: Option<&str>) -> String {
    let mut req = req.clone();
    if let (Some(secret), Some(obj)) = (
        token.map(str::trim).filter(|s| !s.is_empty()),
        req.as_object_mut(),
    ) {
        obj.insert(
            "token".to_string(),
            serde_json::Value::String(secret.to_string()),
        );
    }
    req.to_string()
}

// ---------------------------------------------------------------------------
// The egress wrapper
//
// A node that sends an op through a proxy wraps the request it would have sent:
//
//   {"operation":"egress","egress":{"v":1,"proxy":"socks5h://..."},"inner":{...}}
//
// `inner` is the unchanged request. An engine too old to know the wrapper answers
// "Unknown operation: egress" and sends nothing, which is the point of putting the
// instruction in the operation name rather than in a field an old engine would
// skip over. `encode` still adds `token` at the top level.
// ---------------------------------------------------------------------------

/// The operation name of a wrapped request.
pub const EGRESS_OP: &str = "egress";

/// The fields a wrapper may have. Anything else is an instruction this engine does
/// not understand, and an op whose traffic it might change is refused rather than
/// run without it.
const WRAPPER_FIELDS: [&str; 4] = ["operation", "egress", "inner", "token"];

/// `inner` wrapped with the egress a node chose for it.
pub fn wrap_egress(inner: &serde_json::Value, egress: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({"operation": EGRESS_OP, "egress": egress, "inner": inner})
}

/// The request a line asks for, and the egress it was wrapped with.
///
/// A request with no wrapper comes back as it is, with `None`. A wrapped one comes
/// back as its `inner` request and the `egress` object, unread: what the object
/// means is the HTTP layer's to decide.
///
/// An error is a request that names an egress in a way this function cannot honour
/// to the letter, and the engine refuses it without sending anything:
/// - a wrapper with no `egress`, with an `inner` that is not a request, or with a
///   field it does not know;
/// - a wrapper inside a wrapper;
/// - an `egress` field anywhere but on the wrapper. Each op's parameters skip that
///   name, so it would otherwise be dropped without a word and the op sent by
///   whatever route it would have taken.
pub fn split_egress(
    v: serde_json::Value,
) -> Result<(serde_json::Value, Option<serde_json::Value>), String> {
    let Some(obj) = v.as_object() else {
        return Ok((v, None));
    };
    if obj.get("operation").and_then(|o| o.as_str()) != Some(EGRESS_OP) {
        if obj.contains_key(EGRESS_OP) {
            return Err(stray_egress());
        }
        return Ok((v, None));
    }
    if let Some(k) = obj.keys().find(|k| !WRAPPER_FIELDS.contains(&k.as_str())) {
        return Err(format!(
            "the egress wrapper has a field this engine does not read: {k}"
        ));
    }
    let Some(egress) = obj.get("egress").filter(|e| !e.is_null()) else {
        return Err("the egress wrapper has no egress".to_string());
    };
    let Some(inner) = obj.get("inner").and_then(|i| i.as_object()) else {
        return Err("the egress wrapper has no request inside it".to_string());
    };
    if inner.get("operation").and_then(|o| o.as_str()) == Some(EGRESS_OP) {
        return Err("an egress wrapper inside another is refused".to_string());
    }
    if inner.contains_key(EGRESS_OP) {
        return Err(stray_egress());
    }
    let egress = egress.clone();
    let inner = serde_json::Value::Object(inner.clone());
    Ok((inner, Some(egress)))
}

fn stray_egress() -> String {
    "an egress is read only from the egress wrapper, not from a request's own fields".to_string()
}

#[cfg(test)]
mod egress_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_request_without_a_wrapper_is_left_alone() {
        let req = json!({"operation": "inject", "target": "http://a"});
        assert_eq!(split_egress(req.clone()), Ok((req, None)));
        // Not an object: the daemon's own parsing reports it.
        assert_eq!(split_egress(json!([1])), Ok((json!([1]), None)));
    }

    #[test]
    fn wrap_and_split_are_inverses() {
        let inner = json!({"operation": "crawl", "seed": "http://a", "response": "stream"});
        let egress = json!({"v": 1, "proxy": "socks5h://u:p@127.0.0.1:1"});
        let wrapped = wrap_egress(&inner, &egress);
        assert_eq!(wrapped["operation"], EGRESS_OP);
        assert_eq!(split_egress(wrapped), Ok((inner, Some(egress))));
    }

    #[test]
    fn the_token_rides_on_the_wrapper() {
        let inner = json!({"operation": "scan"});
        let line = encode_with(&wrap_egress(&inner, &json!({"v": 1})), Some("t"));
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["token"], "t");
        let (got, _) = split_egress(v).unwrap();
        assert_eq!(got, inner);
    }

    #[test]
    fn a_malformed_wrapper_is_refused() {
        for bad in [
            json!({"operation": "egress", "inner": {"operation": "scan"}}),
            json!({"operation": "egress", "egress": null, "inner": {"operation": "scan"}}),
            json!({"operation": "egress", "egress": {"v": 1}}),
            json!({"operation": "egress", "egress": {"v": 1}, "inner": "scan"}),
            json!({"operation": "egress", "egress": {"v": 1}, "inner": {"operation": "scan"},
                   "response": "stream"}),
        ] {
            assert!(split_egress(bad.clone()).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_wrapper_inside_a_wrapper_is_refused() {
        let inner = wrap_egress(&json!({"operation": "scan"}), &json!({"v": 1}));
        let e = split_egress(wrap_egress(&inner, &json!({"v": 1}))).unwrap_err();
        assert!(e.contains("inside another"), "{e}");
    }

    #[test]
    fn an_egress_anywhere_but_the_wrapper_is_refused() {
        let bare = json!({"operation": "inject", "egress": {"v": 1, "proxy": null}});
        assert!(split_egress(bare).is_err());
        let inside = wrap_egress(
            &json!({"operation": "inject", "egress": {"v": 1}}),
            &json!({"v": 1}),
        );
        assert!(split_egress(inside).is_err());
    }
}

/// True when a daemon reply line is a terminal error.
///
/// One definition, in one place. Each client used to spell this itself, and the
/// unauthorized reply matched none of them, so a rejected request read as an
/// ordinary line and the client waited for a terminator that never arrived.
pub fn is_error(line: &str) -> bool {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
        return false;
    };
    // Two spellings are in the wild. Stream events use `type`, and so do
    // toolmark and plessor throughout; `status` is what every doorward reply uses and
    // what ambulo and voyage use for their invalid-JSON reply. Both carry the
    // detail in `message`, so only the discriminator differs. Accept either: a
    // client that understands one of them exits 0 on half the failures, which
    // is how `doorward exec` reported success on an unknown operation.
    //
    // A line with a `type` is decided by it alone. Its `status` belongs to what
    // the event describes: an ambulo result for one URL that could not be fetched
    // says `"status":"error"`, and the scan carries on past it.
    match v.get("type") {
        Some(kind) => kind.as_str() == Some("error"),
        None => v.get("status").and_then(|s| s.as_str()) == Some("error"),
    }
}

#[cfg(test)]
mod is_error_tests {
    use super::*;

    #[test]
    fn the_error_envelope_is_recognised() {
        assert!(is_error(r#"{"type":"error","message":"unauthorized"}"#));
        assert!(is_error(
            r#"{"type":"error","message":"Unknown operation: x"}"#
        ));
    }

    #[test]
    fn the_status_spelling_is_recognised_too() {
        // doorward uses this for every reply, and ambulo and voyage for invalid JSON.
        assert!(is_error(
            r#"{"status":"error","message":"Unknown operation: x"}"#
        ));
        assert!(is_error(
            r#"{"status":"error","message":"Invalid JSON: eof"}"#
        ));
    }

    #[test]
    fn a_non_error_status_is_not_an_error() {
        // `status` also carries port state, which must not read as a failure.
        assert!(!is_error(r#"{"status":"open","port":443}"#));
        assert!(!is_error(r#"{"status":"closed","port":22}"#));
    }

    #[test]
    fn one_failed_request_in_a_stream_is_not_a_failed_run() {
        // ambulo reports a URL it could not fetch as a result whose status is
        // `error`, and the scan goes on. Read as terminal, it ended a piped scan
        // halfway through a wordlist with exit 1.
        assert!(!is_error(
            r#"{"type":"result","url":"http://h/x","status":"error","code":"0"}"#
        ));
    }

    #[test]
    fn ordinary_events_are_not_errors() {
        assert!(!is_error(r#"{"type":"ack","total":10}"#));
        assert!(!is_error(r#"{"type":"done"}"#));
        assert!(!is_error("not json at all"));
        assert!(!is_error(""));
    }
}

#[cfg(test)]
mod encode_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn without_a_token_the_envelope_is_unchanged() {
        let v = json!({"operation": "scan"});
        assert_eq!(encode_with(&v, None), v.to_string());
        assert_eq!(encode_with(&v, Some("   ")), v.to_string());
    }

    #[test]
    fn with_a_token_the_envelope_carries_it() {
        let out = encode_with(&json!({"operation": "scan"}), Some("s3cret"));
        let back: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(back["token"], "s3cret");
        assert_eq!(back["operation"], "scan");
    }

    #[test]
    fn a_stamped_envelope_satisfies_the_gate_it_pairs_with() {
        let out = encode_with(&json!({"operation": "scan"}), Some("pair"));
        let back: serde_json::Value = serde_json::from_str(&out).unwrap();
        let gate = Gate {
            secret: Some("pair".into()),
        };
        assert!(gate.allows(back.get("token").and_then(|t| t.as_str())));
    }
}

// ---------------------------------------------------------------------------
// Wordlist path containment

/// Extra directories a wordlist may be read from, separated as PATH is on this OS:
/// by `:` on Unix and by `;` on Windows, where `:` is part of every absolute path.
pub const WORDLIST_ROOTS_ENV: &str = "CFX_WORDLIST_ROOTS";

/// How [`WORDLIST_ROOTS_ENV`]'s separator is named in an error.
const ROOTS_SEPARATED: &str = if cfg!(windows) {
    "semicolon-separated"
} else {
    "colon-separated"
};

/// The name every directory the node makes for one op's hand-over files starts with.
pub const HANDOFF_PREFIX: &str = "cfx-handoff-";

/// Directories any wordlist may be read from without configuration.
///
/// These are where the bundled default ships and where operators keep lists on a
/// scanning host: `/opt/crossfyre/wordlists` and the distro paths on Linux, Homebrew's
/// seclists on macOS, Program Files on Windows. The temporary directories are not
/// among them; see [`handoff_roots`].
fn default_roots() -> Vec<std::path::PathBuf> {
    use std::path::PathBuf;
    #[cfg(windows)]
    {
        let program_files =
            std::env::var_os("ProgramFiles").unwrap_or_else(|| r"C:\Program Files".into());
        vec![
            PathBuf::from(program_files)
                .join("Crossfyre")
                .join("wordlists"),
        ]
    }
    #[cfg(target_os = "macos")]
    {
        vec![
            PathBuf::from("/opt/crossfyre/wordlists"),
            PathBuf::from("/opt/homebrew/share/seclists"),
            PathBuf::from("/usr/local/share/seclists"),
        ]
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        vec![
            PathBuf::from("/opt/crossfyre/wordlists"),
            PathBuf::from("/usr/share/wordlists"),
            PathBuf::from("/usr/share/seclists"),
        ]
    }
}

/// Directories the node hands downloaded wordlists over in, from which only a file
/// directly inside one of its `cfx-handoff-*` directories is read.
///
/// The daemon takes a path from whoever reaches its port, and these directories hold
/// much more than wordlists: anything the operator keeps in a temporary directory, in
/// subdirectories other accounts cannot list, could otherwise be named and read. On
/// Unix the node hands over in /tmp, which on macOS is not a process's own temp dir
/// (that is a per-user directory under /var/folders). Windows hands over in the
/// toolchain directory's `tmp` (the node runs as LocalSystem, whose temp dir the
/// engines cannot read).
fn handoff_roots() -> Vec<std::path::PathBuf> {
    #[cfg(windows)]
    {
        let mut roots = vec![std::env::temp_dir()];
        if let Some(dir) = toolchain_dir() {
            roots.push(dir.join("tmp"));
        }
        roots
    }
    #[cfg(target_os = "macos")]
    {
        vec![std::env::temp_dir(), std::path::PathBuf::from("/tmp")]
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        vec![std::env::temp_dir()]
    }
}

/// Whether `rel`, a path below a hand-over root, names a file directly inside one of
/// the node's `cfx-handoff-*` directories.
fn is_handoff_file(rel: &std::path::Path) -> bool {
    use std::path::Component;
    let mut c = rel.components();
    match (c.next(), c.next(), c.next()) {
        (Some(Component::Normal(dir)), Some(Component::Normal(_)), None) => dir
            .to_str()
            .and_then(|d| d.strip_prefix(HANDOFF_PREFIX))
            .is_some_and(|rest| !rest.is_empty()),
        _ => false,
    }
}

/// The directories in a [`WORDLIST_ROOTS_ENV`] value, split as PATH is split here, each
/// trimmed of spaces, with empty entries left out.
fn roots_from(value: &str) -> Vec<std::path::PathBuf> {
    std::env::split_paths(value)
        .filter_map(|p| {
            let s = p.to_string_lossy();
            let s = s.trim();
            (!s.is_empty()).then(|| std::path::PathBuf::from(s))
        })
        .collect()
}

/// Every directory a wordlist may be read from, defaults plus [`WORDLIST_ROOTS_ENV`].
/// The node's hand-over directories come on top: see [`handoff_roots`].
pub fn wordlist_roots() -> Vec<std::path::PathBuf> {
    let mut roots = default_roots();
    if let Ok(extra) = std::env::var(WORDLIST_ROOTS_ENV) {
        roots.extend(roots_from(&extra));
    }
    roots
}

/// Resolve a caller-supplied wordlist path, refusing anything outside [`wordlist_roots`]
/// that the node did not hand over.
///
/// `wordlist` is a filesystem path chosen by whoever sent the request, and the
/// scanner reads the file and emits one HTTP request per line to a target the
/// same request names. Both ends being caller-controlled made this an arbitrary
/// file read: point it at a credential file and the contents come back as
/// request paths in the attacker's own access log.
///
/// Containment is checked after canonicalisation, so `..` traversal and symlinks
/// into a denied directory are both resolved before the comparison rather than
/// pattern-matched beforehand.
pub fn resolve_wordlist(wordlist: &str) -> Result<std::path::PathBuf, String> {
    resolve_wordlist_with(wordlist, &wordlist_roots(), &handoff_roots())
}

/// The containment decision, without reading the environment. See [`bind_addr_from`].
pub fn resolve_wordlist_in(
    wordlist: &str,
    roots: &[std::path::PathBuf],
) -> Result<std::path::PathBuf, String> {
    resolve_wordlist_with(wordlist, roots, &[])
}

/// [`resolve_wordlist_in`] that also takes a file directly inside a `cfx-handoff-*`
/// directory of one of `handoff`, and nothing else there.
fn resolve_wordlist_with(
    wordlist: &str,
    roots: &[std::path::PathBuf],
    handoff: &[std::path::PathBuf],
) -> Result<std::path::PathBuf, String> {
    let raw = wordlist.trim();
    if raw.is_empty() {
        return Err("wordlist path is empty".to_string());
    }
    // Resolve first: this collapses `..` and follows symlinks, so the path we
    // compare is the file that would actually be opened.
    let real =
        std::fs::canonicalize(raw).map_err(|e| format!("wordlist {raw:?} cannot be read: {e}"))?;
    for root in roots {
        if let Ok(root) = std::fs::canonicalize(root) {
            if real.starts_with(&root) {
                return Ok(real);
            }
        }
    }
    let mut in_handoff_root = false;
    for root in handoff {
        if let Ok(root) = std::fs::canonicalize(root) {
            if let Ok(rel) = real.strip_prefix(&root) {
                if is_handoff_file(rel) {
                    return Ok(real);
                }
                in_handoff_root = true;
            }
        }
    }
    let why = if in_handoff_root {
        "is in a temporary directory, where only the lists the node hands over are read"
    } else {
        "is outside the permitted directories"
    };
    Err(format!(
        "wordlist {} {why}. Move it under one of the permitted directories, or add its \
         directory to {} ({}).",
        real.display(),
        WORDLIST_ROOTS_ENV,
        ROOTS_SEPARATED
    ))
}

/// Open a caller-supplied wordlist once, refusing anything outside [`wordlist_roots`]
/// that the node did not hand over.
///
/// Returns the checked path and the handle every later read has to use, so what is
/// read is the file that was checked. Anything that is not a regular file is refused.
/// On Unix the path is opened one directory at a time without following symlinks,
/// and only through directories no other account can change: see [`open_beneath`].
pub fn open_wordlist(wordlist: &str) -> Result<(std::path::PathBuf, std::fs::File), String> {
    open_wordlist_with(wordlist, &wordlist_roots(), &handoff_roots())
}

/// [`open_wordlist`] with the roots given rather than read from the environment.
pub fn open_wordlist_in(
    wordlist: &str,
    roots: &[std::path::PathBuf],
) -> Result<(std::path::PathBuf, std::fs::File), String> {
    open_wordlist_with(wordlist, roots, &[])
}

fn open_wordlist_with(
    wordlist: &str,
    roots: &[std::path::PathBuf],
    handoff: &[std::path::PathBuf],
) -> Result<(std::path::PathBuf, std::fs::File), String> {
    let real = resolve_wordlist_with(wordlist, roots, handoff)?;
    #[cfg(unix)]
    let file = open_beneath(&real, Operator::current())?;
    #[cfg(not(unix))]
    let file = {
        // Windows opens no directory without FILE_FLAG_BACKUP_SEMANTICS and answers
        // "Access is denied", which would hide what is wrong with the path.
        let file = std::fs::File::open(&real).map_err(|e| {
            if std::fs::metadata(&real).is_ok_and(|m| !m.is_file()) {
                not_a_regular_file(&real)
            } else {
                format!("wordlist {} cannot be opened: {e}", real.display())
            }
        })?;
        let meta = file
            .metadata()
            .map_err(|e| format!("wordlist {} cannot be read: {e}", real.display()))?;
        if !meta.is_file() {
            return Err(not_a_regular_file(&real));
        }
        file
    };
    Ok((real, file))
}

fn not_a_regular_file(real: &std::path::Path) -> String {
    format!("wordlist {} is not a regular file", real.display())
}

/// The account the engine runs as, which decides whose directories it can trust.
#[cfg(unix)]
#[derive(Clone, Copy, Debug)]
struct Operator {
    uid: u32,
    /// The account's primary group when no other account is in it: named after the
    /// account, listing no other member, and no other account's primary group. Write
    /// access for that group is write access for nobody else.
    private_gid: Option<u32>,
    /// macOS's admin group, whose members administer the machine through sudo and so
    /// can already change any directory. Homebrew makes its prefix writable by it.
    admin_gid: Option<u32>,
}

#[cfg(unix)]
impl Operator {
    fn current() -> Operator {
        // SAFETY: geteuid has no preconditions and cannot fail.
        let uid = unsafe { libc::geteuid() };
        Operator {
            uid,
            private_gid: private_group_of(uid),
            admin_gid: admin_group(),
        }
    }

    /// Whether write access for group `gid` is write access for no account that could
    /// not change the directory anyway.
    fn trusts_group(&self, gid: u32) -> bool {
        self.private_gid == Some(gid) || self.admin_gid == Some(gid)
    }
}

/// The admin group on macOS, gid 80, when it is there under that name.
#[cfg(unix)]
fn admin_group() -> Option<u32> {
    #[cfg(target_os = "macos")]
    {
        const ADMIN: u32 = 80;
        group_entry(ADMIN)
            .filter(|g| g.name == b"admin")
            .map(|_| ADMIN)
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

/// The primary group of `uid` when it is private to that account.
#[cfg(unix)]
fn private_group_of(uid: u32) -> Option<u32> {
    let mut buf: Vec<libc::c_char> = vec![0; 4096];
    loop {
        // SAFETY: an all-zero passwd is a valid out-parameter, and getpwuid_r writes
        // only into it and `buf`, whose length it is given.
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut found: *mut libc::passwd = std::ptr::null_mut();
        let rc =
            unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut found) };
        if rc == libc::ERANGE && buf.len() < 1 << 20 {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if rc != 0 || found.is_null() || pwd.pw_name.is_null() {
            return None;
        }
        // SAFETY: on success pw_name is a NUL-terminated string inside `buf`.
        let name = unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) }
            .to_bytes()
            .to_vec();
        return group_is_only(pwd.pw_gid, &name).then_some(pwd.pw_gid);
    }
}

/// A group's name and the members it lists.
#[cfg(unix)]
struct GroupEntry {
    name: Vec<u8>,
    members: Vec<Vec<u8>>,
}

/// The group `gid`, if there is one.
#[cfg(unix)]
fn group_entry(gid: libc::gid_t) -> Option<GroupEntry> {
    use std::ffi::CStr;
    let mut buf: Vec<libc::c_char> = vec![0; 4096];
    loop {
        // SAFETY: as in private_group_of, for getgrgid_r and a group.
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut found: *mut libc::group = std::ptr::null_mut();
        let rc =
            unsafe { libc::getgrgid_r(gid, &mut grp, buf.as_mut_ptr(), buf.len(), &mut found) };
        if rc == libc::ERANGE && buf.len() < 1 << 20 {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if rc != 0 || found.is_null() || grp.gr_name.is_null() {
            return None;
        }
        // SAFETY: on success gr_name is a NUL-terminated string and gr_mem a
        // NULL-terminated array of them, all inside `buf`.
        let name = unsafe { CStr::from_ptr(grp.gr_name) }.to_bytes().to_vec();
        let mut members = Vec::new();
        let mut member = grp.gr_mem;
        while !member.is_null() {
            let m = unsafe { *member };
            if m.is_null() {
                break;
            }
            members.push(unsafe { CStr::from_ptr(m) }.to_bytes().to_vec());
            member = unsafe { member.add(1) };
        }
        return Some(GroupEntry { name, members });
    }
}

/// The names of the accounts whose primary group is `gid`. An account is in its
/// primary group without the group listing it.
#[cfg(unix)]
fn primary_members(gid: libc::gid_t) -> Vec<Vec<u8>> {
    // getpwent walks one process-wide cursor, so one walk at a time.
    static WALK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _walk = WALK.lock().unwrap_or_else(|p| p.into_inner());
    let mut names = Vec::new();
    // SAFETY: setpwent, getpwent and endpwent have no preconditions. Each entry
    // getpwent returns is read before the next call, which may overwrite it.
    unsafe {
        libc::setpwent();
        loop {
            let pwd = libc::getpwent();
            if pwd.is_null() {
                break;
            }
            if (*pwd).pw_gid == gid && !(*pwd).pw_name.is_null() {
                names.push(std::ffi::CStr::from_ptr((*pwd).pw_name).to_bytes().to_vec());
            }
        }
        libc::endpwent();
    }
    names
}

/// Whether group `gid` is named `name` and has no member but `name`.
#[cfg(unix)]
fn group_is_only(gid: libc::gid_t, name: &[u8]) -> bool {
    let Some(group) = group_entry(gid) else {
        return false;
    };
    // The account database is walked only for a group that could pass.
    only_member(name, &group, &[]) && only_member(name, &group, &primary_members(gid))
}

/// The decision behind [`group_is_only`]: the group is named `name`, and neither its
/// listed members nor the accounts in `primary`, those whose primary group it is,
/// include anyone else.
#[cfg(unix)]
fn only_member(name: &[u8], group: &GroupEntry, primary: &[Vec<u8>]) -> bool {
    group.name == name
        && group.members.iter().all(|m| m == name)
        && primary.iter().all(|m| m == name)
}

/// Open `real`, a canonical path, one component at a time from `/` without following
/// any symlink, and return the regular file at its end.
///
/// Each directory on the way has to be one that only this account or root can
/// change, so no name on the path can have been made, moved or removed by anyone
/// else. A directory every account can write is accepted only with the sticky bit,
/// as /tmp has: there other accounts can add names but cannot remove or rename one
/// that leads to a file they do not own. A name they added could still be a second
/// hard link to another account's file, so in such a directory a file with more
/// than one link is read only when every account may read it anyway.
#[cfg(unix)]
fn open_beneath(real: &std::path::Path, op: Operator) -> Result<std::fs::File, String> {
    use std::os::unix::fs::MetadataExt;
    use std::path::Component;

    let changed = || {
        format!(
            "wordlist {} changed while it was being opened",
            real.display()
        )
    };
    let mut names = Vec::new();
    for c in real.components() {
        match c {
            Component::RootDir => {}
            Component::Normal(n) => names.push(n),
            _ => return Err(changed()),
        }
    }
    let Some((file_name, dirs)) = names.split_last() else {
        return Err(not_a_regular_file(real));
    };
    let opening = |e: std::io::Error| match e.raw_os_error() {
        Some(libc::ELOOP) | Some(libc::ENOTDIR) => changed(),
        _ => format!("wordlist {} cannot be opened: {e}", real.display()),
    };

    let mut at = std::path::PathBuf::from("/");
    let mut dir = open_at(None, std::ffi::OsStr::new("/"), DIR_FLAGS).map_err(opening)?;
    let mut shared = trusted_dir(&dir, &at, op).map_err(|e| e.unwrap_or_else(changed))?;
    for name in dirs {
        at.push(name);
        dir = open_at(Some(&dir), name, DIR_FLAGS).map_err(opening)?;
        shared = trusted_dir(&dir, &at, op).map_err(|e| e.unwrap_or_else(changed))?;
    }
    // O_NONBLOCK so that a FIFO is opened at once and then refused below, rather than
    // holding this call until something writes to it. A regular file is unaffected.
    let file = open_at(
        Some(&dir),
        file_name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
    )
    .map_err(opening)?;
    let meta = file
        .metadata()
        .map_err(|e| format!("wordlist {} cannot be read: {e}", real.display()))?;
    if !meta.is_file() {
        return Err(not_a_regular_file(real));
    }
    if shared && meta.nlink() > 1 && meta.mode() & 0o004 == 0 {
        return Err(format!(
            "wordlist {} has more than one hard link and is not readable by everyone. \
             Copy it to a file of its own.",
            real.display()
        ));
    }
    Ok(file)
}

/// How each directory on the way is opened. On Linux O_PATH lets a directory that
/// may be searched but not listed be passed through, as a path lookup would.
#[cfg(any(target_os = "linux", target_os = "android"))]
const DIR_FLAGS: libc::c_int = libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW;
#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
const DIR_FLAGS: libc::c_int = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW;

#[cfg(unix)]
fn open_at(
    dir: Option<&std::fs::File>,
    name: &std::ffi::OsStr,
    flags: libc::c_int,
) -> std::io::Result<std::fs::File> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::{AsRawFd, FromRawFd};
    let c = std::ffi::CString::new(name.as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let at = dir.map_or(libc::AT_FDCWD, |d| d.as_raw_fd());
    // SAFETY: `c` is NUL-terminated and outlives the call; nothing is created, so no
    // mode argument is read.
    let fd = unsafe { libc::openat(at, c.as_ptr(), flags | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: openat returned a new descriptor that nothing else owns.
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

/// Whether the directory open at `dir` is one the wordlist may be reached through.
///
/// `Ok(true)` is a sticky directory other accounts can write; `Ok(false)` one only
/// this account, root and a group [`Operator::trusts_group`] can. `Err(None)` means it is not a directory at all, which
/// can only be a name changed under the walk.
#[cfg(unix)]
fn trusted_dir(
    dir: &std::fs::File,
    at: &std::path::Path,
    op: Operator,
) -> Result<bool, Option<String>> {
    use std::os::unix::fs::MetadataExt;
    let meta = dir
        .metadata()
        .map_err(|e| Some(format!("{} cannot be read: {e}", at.display())))?;
    if !meta.is_dir() {
        return Err(None);
    }
    if meta.uid() != op.uid && meta.uid() != 0 {
        return Err(Some(format!(
            "wordlist directory {} belongs to another account, which could change what \
             is in it. Move the wordlist to a directory of your own.",
            at.display()
        )));
    }
    let mode = meta.mode();
    let others_write = mode & 0o002 != 0;
    let group_write = mode & 0o020 != 0 && !op.trusts_group(meta.gid());
    let shared = others_write || group_write;
    if shared && mode & 0o1000 == 0 {
        return Err(Some(format!(
            "wordlist directory {} can be written by other accounts. Move the wordlist \
             to a directory only you can write.",
            at.display()
        )));
    }
    Ok(shared)
}

#[cfg(test)]
mod wordlist_tests {
    use super::*;
    use std::io::Write;

    fn tmp_with(name: &str, body: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        p
    }

    #[test]
    fn a_file_inside_a_root_resolves() {
        let p = tmp_with("dguard-allowed.txt", "admin\n");
        let roots = vec![std::env::temp_dir()];
        assert!(resolve_wordlist_in(p.to_str().unwrap(), &roots).is_ok());
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn a_file_outside_every_root_is_refused() {
        let p = tmp_with("dguard-outside.txt", "x\n");
        // A root that does not contain the file.
        let roots = vec![std::path::PathBuf::from("/opt/crossfyre/wordlists")];
        let err = resolve_wordlist_in(p.to_str().unwrap(), &roots).unwrap_err();
        assert!(err.contains(WORDLIST_ROOTS_ENV), "{err}");
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn traversal_out_of_a_root_is_refused() {
        // The exact shape of the original read: a path that starts inside an
        // allowed root and climbs out of it.
        let escape = std::env::temp_dir().join("../etc/hostname");
        let roots = vec![std::env::temp_dir()];
        assert!(resolve_wordlist_in(escape.to_str().unwrap(), &roots).is_err());
    }

    #[test]
    fn a_missing_file_is_refused_rather_than_allowed() {
        let roots = vec![std::env::temp_dir()];
        let p = std::env::temp_dir().join("dguard-does-not-exist-xyz.txt");
        assert!(resolve_wordlist_in(p.to_str().unwrap(), &roots).is_err());
    }

    #[test]
    fn an_empty_path_is_refused() {
        assert!(resolve_wordlist_in("   ", &[std::env::temp_dir()]).is_err());
    }

    #[test]
    fn the_extra_roots_are_split_as_path_is() {
        let a = std::env::temp_dir().join("lists a");
        let b = std::env::temp_dir().join("lists-b");
        let joined = std::env::join_paths([&a, &b]).expect("joinable");
        assert_eq!(roots_from(joined.to_str().expect("utf-8")), vec![a, b]);
        assert!(roots_from("").is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn on_unix_a_colon_separates_and_spaces_around_an_entry_go() {
        assert_eq!(
            roots_from(" /srv/lists : :/opt/more"),
            vec![
                std::path::PathBuf::from("/srv/lists"),
                std::path::PathBuf::from("/opt/more")
            ]
        );
    }

    // The bug this replaced split on ':', which cut every Windows path in two at its
    // drive letter.
    #[cfg(windows)]
    #[test]
    fn on_windows_a_drive_letter_is_part_of_the_path() {
        assert_eq!(
            roots_from(r"C:\lists;D:\more lists"),
            vec![
                std::path::PathBuf::from(r"C:\lists"),
                std::path::PathBuf::from(r"D:\more lists")
            ]
        );
    }

    // The node hands wordlists over in /tmp on macOS, which is not the engine's own
    // temp dir there.
    #[cfg(target_os = "macos")]
    #[test]
    fn on_macos_the_node_s_hand_over_directory_is_a_root() {
        assert!(handoff_roots().contains(&std::path::PathBuf::from("/tmp")));
    }

    // A temporary directory holds whatever the operator keeps there, so it is not a
    // place any wordlist may come from, only the ones the node hands over.
    #[test]
    fn the_temp_dir_takes_only_hand_overs() {
        assert!(!default_roots().contains(&std::env::temp_dir()));
        assert!(handoff_roots().contains(&std::env::temp_dir()));
    }

    #[test]
    fn in_a_hand_over_root_only_the_node_s_hand_over_files_are_read() {
        let tmp = scratch_root("handoff-root");
        let mkdir = |p: &std::path::Path| {
            std::fs::create_dir(p).unwrap();
            #[cfg(unix)]
            chmod(p, 0o700);
        };
        // The node's layout: a new cfx-handoff-* directory per op, the list in it.
        let op = tmp.join("cfx-handoff-a1B2c3");
        mkdir(&op);
        let wl = op.join("cfx-wl-sub-1.txt");
        std::fs::write(&wl, "www\n").unwrap();
        let open = |p: &std::path::Path| {
            open_wordlist_with(p.to_str().unwrap(), &[], std::slice::from_ref(&tmp))
        };
        assert!(open(&wl).is_ok());

        // Anything else the operator keeps there, even behind a directory only the
        // operator can open, is not a wordlist.
        let private = tmp.join("private");
        mkdir(&private);
        let secret = private.join("secret.toml");
        std::fs::write(&secret, "token = \"x\"\n").unwrap();
        let loose = tmp.join("loose.txt");
        std::fs::write(&loose, "a\n").unwrap();
        let deeper = op.join("sub");
        mkdir(&deeper);
        std::fs::write(deeper.join("wl.txt"), "a\n").unwrap();
        let bare = tmp.join(HANDOFF_PREFIX);
        mkdir(&bare);
        std::fs::write(bare.join("wl.txt"), "a\n").unwrap();
        for p in [
            secret.clone(),
            loose,
            deeper.join("wl.txt"),
            bare.join("wl.txt"),
        ] {
            let err = open(&p).unwrap_err();
            assert!(err.contains("only the lists the node hands over"), "{err}");
            assert!(err.contains(WORDLIST_ROOTS_ENV), "{err}");
        }
        // Naming the directory as a root of its own still works.
        assert!(
            open_wordlist_with(
                secret.to_str().unwrap(),
                std::slice::from_ref(&private),
                std::slice::from_ref(&tmp)
            )
            .is_ok()
        );
        let _ = std::fs::remove_dir_all(tmp);
    }

    /// A fresh directory under the temp dir, used as the only root.
    fn scratch_root(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("dguard-open-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        // Writable by its owner alone, whatever the umask.
        #[cfg(unix)]
        chmod(&d, 0o755);
        std::fs::canonicalize(d).unwrap()
    }

    #[test]
    fn a_regular_file_inside_a_root_opens_and_reads_through_the_handle() {
        use std::io::Read;
        let root = scratch_root("plain");
        let p = root.join("wl.txt");
        std::fs::write(&p, "admin\n").unwrap();
        let (real, mut f) = open_wordlist_in(p.to_str().unwrap(), &[root.clone()]).unwrap();
        assert_eq!(real, p);
        let mut got = String::new();
        f.read_to_string(&mut got).unwrap();
        assert_eq!(got, "admin\n");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_directory_inside_a_root_is_not_a_wordlist() {
        let root = scratch_root("dir");
        let d = root.join("sub");
        std::fs::create_dir(&d).unwrap();
        let err = open_wordlist_in(d.to_str().unwrap(), &[root.clone()]).unwrap_err();
        assert!(err.contains("not a regular file"), "{err}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_is_refused_without_waiting_for_a_writer() {
        let root = scratch_root("fifo");
        let p = root.join("wl");
        let c = std::ffi::CString::new(p.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let err = open_wordlist_in(p.to_str().unwrap(), &[root.clone()]).unwrap_err();
        assert!(err.contains("not a regular file"), "{err}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    fn chmod(p: &std::path::Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    // The walk is given a path that was canonical when it was checked. A symlink that
    // has taken the place of a directory or of the file since then is not followed.
    #[cfg(unix)]
    #[test]
    fn a_symlink_on_the_way_is_not_followed() {
        let root = scratch_root("symlink");
        std::fs::create_dir(root.join("sub")).unwrap();
        std::fs::write(root.join("sub/wl.txt"), "a\n").unwrap();
        std::os::unix::fs::symlink(root.join("sub"), root.join("dir")).unwrap();
        std::os::unix::fs::symlink(root.join("sub/wl.txt"), root.join("file")).unwrap();
        for p in [root.join("dir/wl.txt"), root.join("file")] {
            let err = open_beneath(&p, Operator::current()).unwrap_err();
            assert!(err.contains("changed while it was being opened"), "{err}");
        }
        assert!(open_beneath(&root.join("sub/wl.txt"), Operator::current()).is_ok());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_that_belongs_to_another_account_is_refused() {
        let me = Operator::current();
        if me.uid == 0 {
            // Root's own directories are trusted for every account.
            return;
        }
        let root = scratch_root("owner");
        let p = root.join("wl.txt");
        std::fs::write(&p, "a\n").unwrap();
        let someone_else = Operator {
            uid: me.uid + 1,
            private_gid: None,
            admin_gid: None,
        };
        let err = open_beneath(&p, someone_else).unwrap_err();
        assert!(err.contains("belongs to another account"), "{err}");
        assert!(open_beneath(&p, me).is_ok());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn group_write_is_trusted_only_for_the_accounts_private_group() {
        use std::os::unix::fs::MetadataExt;
        let root = scratch_root("group");
        let dir = root.join("g");
        std::fs::create_dir(&dir).unwrap();
        chmod(&dir, 0o770);
        let p = dir.join("wl.txt");
        std::fs::write(&p, "a\n").unwrap();
        let gid = std::fs::metadata(&dir).unwrap().gid();
        let uid = Operator::current().uid;
        let private = Operator {
            uid,
            private_gid: Some(gid),
            admin_gid: None,
        };
        assert!(open_beneath(&p, private).is_ok());
        let shared = Operator {
            uid,
            private_gid: None,
            admin_gid: None,
        };
        let err = open_beneath(&p, shared).unwrap_err();
        assert!(err.contains("can be written by other accounts"), "{err}");
        let _ = std::fs::remove_dir_all(root);
    }

    // Homebrew makes its prefix writable by the admin group on macOS, so its seclists
    // are reached through directories that group can write. Its members can already
    // change any directory through sudo.
    #[cfg(unix)]
    #[test]
    fn group_write_is_trusted_for_the_admin_group() {
        use std::os::unix::fs::MetadataExt;
        let root = scratch_root("admin");
        let dir = root.join("share");
        std::fs::create_dir(&dir).unwrap();
        chmod(&dir, 0o775);
        let p = dir.join("wl.txt");
        std::fs::write(&p, "a\n").unwrap();
        let gid = std::fs::metadata(&dir).unwrap().gid();
        let uid = Operator::current().uid;
        let admin = Operator {
            uid,
            private_gid: None,
            admin_gid: Some(gid),
        };
        assert!(open_beneath(&p, admin).is_ok());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn on_macos_a_directory_the_admin_group_can_write_is_trusted() {
        let me = Operator::current();
        assert_eq!(me.admin_gid, Some(80));
        let root = scratch_root("brew");
        let dir = root.join("share");
        std::fs::create_dir(&dir).unwrap();
        chmod(&dir, 0o775);
        let p = dir.join("wl.txt");
        std::fs::write(&p, "a\n").unwrap();
        // Only an account in the admin group can give it a directory.
        if std::os::unix::fs::chown(&dir, None, Some(80)).is_ok() {
            assert!(open_beneath(&p, me).is_ok());
        }
        let _ = std::fs::remove_dir_all(root);
    }

    // Elsewhere a group called admin is just a group.
    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn off_macos_no_admin_group_is_trusted() {
        assert_eq!(Operator::current().admin_gid, None);
    }

    // An account is in its primary group without the group listing it, so a group
    // named after the operator that is another account's primary group is shared.
    #[cfg(unix)]
    #[test]
    fn a_group_that_is_another_account_s_primary_group_is_not_private() {
        let own = GroupEntry {
            name: b"op".to_vec(),
            members: vec![],
        };
        assert!(only_member(b"op", &own, &[b"op".to_vec()]));
        let shared = [b"op".to_vec(), b"other".to_vec()];
        assert!(!only_member(b"op", &own, &shared));
        let listed = GroupEntry {
            name: b"op".to_vec(),
            members: vec![b"op".to_vec(), b"other".to_vec()],
        };
        assert!(!only_member(b"op", &listed, &[]));
        let named = GroupEntry {
            name: b"staff".to_vec(),
            members: vec![],
        };
        assert!(!only_member(b"op", &named, &[]));
    }

    #[cfg(unix)]
    #[test]
    fn the_account_database_walk_finds_primary_members() {
        assert!(primary_members(0).iter().any(|n| n == b"root"));
    }

    // In a directory other accounts can write, its names can change between any two
    // looks at them, so nothing learned about the file found there would hold. The
    // directory is refused, whatever its names point at from one moment to the next.
    #[cfg(unix)]
    #[test]
    fn a_directory_others_can_write_is_refused_however_its_names_change() {
        use std::io::Read;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        let root = scratch_root("race");
        let open = root.join("open");
        std::fs::create_dir(&open).unwrap();
        chmod(&open, 0o777);
        let outside = scratch_root("race-outside");
        let private = outside.join("private.txt");
        std::fs::write(&private, "secret\n").unwrap();
        chmod(&private, 0o600);
        let wl = open.join("wl");

        let stop = Arc::new(AtomicBool::new(false));
        let changer = {
            let (private, wl, stop) = (private.clone(), wl.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    let _ = std::fs::hard_link(&private, &wl);
                    let _ = std::fs::remove_file(&wl);
                }
            })
        };
        let (mut refused, mut leaked) = (0, None);
        for _ in 0..2000 {
            match open_wordlist_in(wl.to_str().unwrap(), &[root.clone()]) {
                Ok((_, mut f)) => {
                    let mut got = String::new();
                    let _ = f.read_to_string(&mut got);
                    if got.contains("secret") {
                        leaked = Some(got);
                        break;
                    }
                }
                Err(e) if e.contains("can be written by other accounts") => refused += 1,
                Err(_) => {}
            }
        }
        stop.store(true, Ordering::SeqCst);
        changer.join().unwrap();
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(outside);
        assert_eq!(leaked, None, "read a file outside the roots");
        assert!(refused > 0);
    }

    // A sticky directory every account can write, such as /tmp, is where the node
    // hands wordlists over. Other accounts can add a hard link there but cannot remove
    // one to a file they do not own, so a second link is a stable sign.
    #[cfg(unix)]
    #[test]
    fn in_a_sticky_shared_directory_a_private_file_with_a_second_link_is_refused() {
        let root = scratch_root("sticky");
        let shared = root.join("shared");
        std::fs::create_dir(&shared).unwrap();
        chmod(&shared, 0o1777);
        let private = root.join("private.txt");
        std::fs::write(&private, "secret\n").unwrap();
        chmod(&private, 0o600);
        let linked = shared.join("wl.txt");
        std::fs::hard_link(&private, &linked).unwrap();
        let err = open_wordlist_in(linked.to_str().unwrap(), &[root.clone()]).unwrap_err();
        assert!(err.contains("hard link"), "{err}");
        // Outside a shared directory a second link changes nothing.
        assert!(open_wordlist_in(private.to_str().unwrap(), &[root.clone()]).is_ok());
        chmod(&private, 0o644);
        assert!(open_wordlist_in(linked.to_str().unwrap(), &[root.clone()]).is_ok());
        // A private file of its own, as the node writes, is read.
        let single = shared.join("cfx-wl-1.txt");
        std::fs::write(&single, "a\n").unwrap();
        chmod(&single, 0o600);
        assert!(open_wordlist_in(single.to_str().unwrap(), &[root.clone()]).is_ok());
        let _ = std::fs::remove_dir_all(root);
    }

    // Through the defaults, as a request reaches the daemon: a file the operator keeps
    // in the temp dir, behind a directory no other account can open, is not read.
    #[test]
    fn a_private_file_in_the_temp_dir_is_not_a_wordlist_by_default() {
        if std::env::var_os(WORDLIST_ROOTS_ENV).is_some() {
            return;
        }
        let dir = std::env::temp_dir().join(format!("dguard-private-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        #[cfg(unix)]
        chmod(&dir, 0o700);
        let secret = dir.join("secret.toml");
        std::fs::write(&secret, "token = \"x\"\n").unwrap();
        let got = open_wordlist(secret.to_str().unwrap());
        let _ = std::fs::remove_dir_all(&dir);
        let err = got.expect_err("read a private file from the temp dir");
        assert!(err.contains(WORDLIST_ROOTS_ENV), "{err}");
    }

    #[test]
    fn opening_still_refuses_a_file_outside_every_root() {
        let root = scratch_root("outside");
        let outside = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
        let err = open_wordlist_in(outside, &[root.clone()]).unwrap_err();
        assert!(err.contains(WORDLIST_ROOTS_ENV), "{err}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn the_refusal_names_the_separator_this_os_uses() {
        let p = tmp_with("dguard-separator.txt", "x\n");
        let err = resolve_wordlist_in(p.to_str().unwrap(), &[]).unwrap_err();
        let _ = std::fs::remove_file(p);
        let want = if cfg!(windows) { "semicolon" } else { "colon" };
        assert!(err.contains(&format!("({want}-separated)")), "{err}");
    }
}

// ---------------------------------------------------------------------------
// The toolchain directory
// ---------------------------------------------------------------------------

/// The variable that names the toolchain directory, which holds `config.toml`. The
/// engine host sets it for the engines it starts on macOS and Windows.
pub const TOOLCHAIN_DIR_ENV: &str = "CROSSFYRE_TOOLCHAIN_DIR";

/// The toolchain directory: the one [`TOOLCHAIN_DIR_ENV`] names, else
/// `~/.config/crossfyre` on Linux and `crossfyre` in the per-user config directory
/// elsewhere (`~/Library/Application Support` on macOS, `%APPDATA%` on Windows), which
/// is where the CLI writes it. None when there is no home directory to look in.
pub fn toolchain_dir() -> Option<std::path::PathBuf> {
    toolchain_dir_from(std::env::var_os(TOOLCHAIN_DIR_ENV))
}

/// [`toolchain_dir`] given the variable's value, so it is tested without changing the
/// environment. An empty value names nothing.
fn toolchain_dir_from(named: Option<std::ffi::OsString>) -> Option<std::path::PathBuf> {
    if let Some(dir) = named.filter(|d| !d.is_empty()) {
        return Some(dir.into());
    }
    let root = if cfg!(target_os = "linux") {
        dirs::home_dir()?.join(".config")
    } else {
        dirs::config_dir()?
    };
    Some(root.join("crossfyre"))
}

#[cfg(test)]
mod toolchain_dir_tests {
    use super::toolchain_dir_from;
    use std::path::PathBuf;

    #[test]
    fn the_directory_the_variable_names_is_the_one_used() {
        assert_eq!(
            toolchain_dir_from(Some("/srv/cfx".into())),
            Some(PathBuf::from("/srv/cfx"))
        );
    }

    #[test]
    fn an_empty_variable_names_nothing() {
        assert_eq!(
            toolchain_dir_from(Some("".into())),
            toolchain_dir_from(None)
        );
    }

    /// ~/.config on Linux whatever XDG_CONFIG_HOME says, as under sudo the CLI finds the
    /// invoking user's, and the platform's config directory elsewhere.
    #[test]
    fn without_the_variable_it_is_in_the_user_s_config_directory() {
        let home = dirs::home_dir().expect("a home directory");
        let dir = toolchain_dir_from(None).expect("a toolchain directory");
        if cfg!(target_os = "linux") {
            assert_eq!(dir, home.join(".config").join("crossfyre"));
        } else {
            assert_eq!(dir, dirs::config_dir().unwrap().join("crossfyre"));
            assert!(dir.starts_with(&home), "{}", dir.display());
        }
    }
}

// ---------------------------------------------------------------------------
// Startup dependencies
// ---------------------------------------------------------------------------

/// How [`wait_for`] begins each line that says what a daemon waits for. A client that
/// started the daemon reads it in the daemon's log, and stops waiting itself.
pub(crate) const WAITING: &str = "[dguard] waiting for ";

/// Wait for a dependency the daemon cannot start without, instead of dying.
///
/// ambulo, doorward and voyage open Postgres at startup. When the database went away
/// they exited, systemd restarted them, and they exited again: one host racked
/// up 2,663 restarts over a day and the only symptom anyone saw was three
/// engines being "down" with no reason attached. The database being briefly
/// unreachable is not a reason to give up permanently, and a crash loop is the
/// worst possible way to report it.
///
/// So retry with a capped backoff, and say what is being waited on and why
/// every time, because a daemon that is quietly waiting looks exactly like a
/// daemon that is quietly broken.
///
/// Returns once `attempt` succeeds. Gives up only after `give_up_after`, which
/// is deliberately long: an operator restarting Postgres should not have to
/// restart the engines afterwards.
pub async fn wait_for<T, E, F, Fut>(
    what: &str,
    give_up_after: std::time::Duration,
    mut attempt: F,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let started = std::time::Instant::now();
    let mut wait = std::time::Duration::from_secs(1);
    let mut tries: u32 = 0;
    loop {
        match attempt().await {
            Ok(v) => {
                if tries > 0 {
                    eprintln!(
                        "[dguard] {what} is available again after {tries} attempt(s), {}s",
                        started.elapsed().as_secs()
                    );
                }
                return Ok(v);
            }
            Err(e) => {
                tries += 1;
                if started.elapsed() >= give_up_after {
                    eprintln!(
                        "[dguard] giving up on {what} after {}s: {e}",
                        started.elapsed().as_secs()
                    );
                    return Err(e);
                }
                eprintln!(
                    "{WAITING}{what}: {e} (attempt {tries}, retrying in {}s)",
                    wait.as_secs()
                );
                tokio::time::sleep(wait).await;
                wait = (wait * 2).min(std::time::Duration::from_secs(30));
            }
        }
    }
}

#[cfg(test)]
mod wait_for_tests {
    use super::wait_for;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    #[tokio::test]
    async fn retries_until_the_dependency_comes_back() {
        let calls = AtomicU32::new(0);
        let got: Result<&str, String> = wait_for("test dep", Duration::from_secs(30), || async {
            if calls.fetch_add(1, Ordering::SeqCst) < 2 {
                Err("not yet".to_string())
            } else {
                Ok("connected")
            }
        })
        .await;
        assert_eq!(got.unwrap(), "connected");
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn eventually_gives_up_and_says_so() {
        let got: Result<(), String> = wait_for("test dep", Duration::from_millis(1), || async {
            Err("still down".to_string())
        })
        .await;
        assert_eq!(got.unwrap_err(), "still down");
    }
}

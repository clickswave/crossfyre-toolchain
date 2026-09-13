//! Inbound listener policy for the engine daemons.
//!
//! The daemons speak newline-delimited JSON over raw TCP. There is no session,
//! no handshake and no per-connection state, so **the bind address is the
//! security boundary**. They used to bind `0.0.0.0`, which put an unauthenticated
//! command channel on every interface: anyone who could reach the port could
//! drive a scan, and `mach`'s wordlist parameter is a filesystem path, so they
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

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

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

/// Extra directories a wordlist may be read from, colon-separated.
pub const WORDLIST_ROOTS_ENV: &str = "CFX_WORDLIST_ROOTS";

/// Directories a wordlist may be read from without configuration.
///
/// These are the two places wordlists actually come from in normal operation:
/// the node downloads remote lists to the temp dir as `cfx-wl-<id>.txt`, and the
/// bundled default ships in `/opt/crossfyre/wordlists`. The distro paths are
/// included because they are where operators keep lists on a scanning host.
fn default_roots() -> Vec<std::path::PathBuf> {
    vec![
        std::env::temp_dir(),
        std::path::PathBuf::from("/opt/crossfyre/wordlists"),
        std::path::PathBuf::from("/usr/share/wordlists"),
        std::path::PathBuf::from("/usr/share/seclists"),
    ]
}

/// Every directory a wordlist may be read from, defaults plus [`WORDLIST_ROOTS_ENV`].
pub fn wordlist_roots() -> Vec<std::path::PathBuf> {
    let mut roots = default_roots();
    if let Ok(extra) = std::env::var(WORDLIST_ROOTS_ENV) {
        roots.extend(
            extra
                .split(':')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(std::path::PathBuf::from),
        );
    }
    roots
}

/// Resolve a caller-supplied wordlist path, refusing anything outside [`wordlist_roots`].
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
    resolve_wordlist_in(wordlist, &wordlist_roots())
}

/// The containment decision, without reading the environment. See [`bind_addr_from`].
pub fn resolve_wordlist_in(
    wordlist: &str,
    roots: &[std::path::PathBuf],
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
    Err(format!(
        "wordlist {} is outside the permitted directories. Move it under one of \
         them, or add its directory to {} (colon-separated).",
        real.display(),
        WORDLIST_ROOTS_ENV
    ))
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
}

// ---------------------------------------------------------------------------
// Startup dependencies
// ---------------------------------------------------------------------------

/// Wait for a dependency the daemon cannot start without, instead of dying.
///
/// mach, pulse and voyage open Postgres at startup. When the database went away
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
                    "[dguard] waiting for {what}: {e} (attempt {tries}, retrying in {}s)",
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

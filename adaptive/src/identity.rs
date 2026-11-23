//! Outbound request identity: the User-Agent and browser hint headers the
//! engines present on the wire.
//!
//! ## Open baseline
//!
//! This public baseline returns a single, honest, current desktop-Chrome
//! identity with a coherent header set and performs **no rotation**. It exists so
//! the open toolchain presents a plausible, non-self-identifying client rather
//! than a scanner banner. The tuned profile catalogue and per-target rotation is
//! in the pacing module; keep these types stable, since it answers in their shapes.
//!
//! Coherence is the whole point: bot-detection cross-checks the User-Agent
//! against the header set (and, with real fingerprint parity, the TLS/HTTP2
//! handshake), so the UA and the headers must always describe the *same* browser.

/// How the caller wants to present on the wire.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Mode {
    /// Blend in as a real, current browser. The default for external targets.
    Evasive,
    /// A neutral, honest client, no blending. For targets you control or that do
    /// not gate on client fingerprint (internal, CTF, dev, allow-listed).
    Fast,
    /// Blend in as a browser, but also carry an attribution token so an
    /// authorized program can allow-list the traffic. The value is the token
    /// (e.g. a bug-bounty handle).
    Identify(String),
}

impl Mode {
    /// Build a mode from the scan/node Evasiveness flags. An `identify` token
    /// (attribution for an authorized program) takes precedence; otherwise
    /// `evasive` chooses blend-in vs a neutral honest client.
    pub fn from_flags(evasive: bool, identify: Option<String>) -> Mode {
        match identify {
            Some(t) if !t.is_empty() => Mode::Identify(t),
            _ if evasive => Mode::Evasive,
            _ => Mode::Fast,
        }
    }
}

/// A coherent browser identity: a User-Agent plus the hint headers a real browser
/// sends alongside it. Keep the two consistent.
#[derive(Clone, Debug)]
pub struct Identity {
    /// The `User-Agent` header value.
    pub user_agent: String,
    /// Default request headers as `(name, value)` pairs, a browser-plausible set.
    /// Header names are static; values may be owned. Does not include
    /// `User-Agent` (set that from [`Identity::user_agent`]).
    pub headers: Vec<(&'static str, String)>,
}

/// Resolve the identity to present for `mode`. `seed` (e.g. the target host) lets
/// a rotation policy pick a stable-per-target profile; this baseline ignores it
/// and always returns the same honest identity.
pub fn resolve(mode: &Mode, seed: Option<&str>) -> Identity {
    from_module(mode, seed).unwrap_or_else(|| baseline(mode))
}

fn baseline(mode: &Mode) -> Identity {
    match mode {
        // The baseline has no catalogue, so every mode maps to the one honest
        // desktop-Chrome identity. `Identify` additionally advertises the token.
        Mode::Identify(token) => {
            let mut id = chrome_desktop();
            id.headers.push((ATTRIBUTION, token.clone()));
            id
        }
        _ => chrome_desktop(),
    }
}

/// Headers an identity may not set: the transport's own, and credentials.
const NOT_AN_IDENTITY: [&str; 9] = [
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "cookie",
    "authorization",
    "proxy-authorization",
    "te",
    "upgrade",
];

/// The installed module's identity for `mode` and `seed`, kept per pair, as a
/// module's answer for one never changes. None without a module, or when its answer
/// is not a clean identity: a User-Agent and at most 32 headers, every name an HTTP
/// token and every value printable on one line, none of the transport's headers or
/// credentials, and in `Identify` mode the attribution header carrying the token.
fn from_module(mode: &Mode, seed: Option<&str>) -> Option<Identity> {
    use std::collections::HashMap;
    use std::sync::Mutex;
    #[derive(serde::Serialize)]
    struct Ask<'a> {
        mode: &'static str,
        token: Option<&'a str>,
        seed: Option<&'a str>,
    }
    #[derive(serde::Deserialize)]
    struct Answer {
        user_agent: String,
        headers: Vec<(String, String)>,
    }
    type Kept = Mutex<HashMap<(Mode, Option<String>), Option<Identity>>>;
    static KEPT: std::sync::OnceLock<Kept> = std::sync::OnceLock::new();
    if !crate::backend::installed() {
        return None;
    }
    let kept = KEPT.get_or_init(|| Mutex::new(HashMap::new()));
    let key = (mode.clone(), seed.map(str::to_string));
    if let Some(id) = kept.lock().ok()?.get(&key) {
        return id.clone();
    }
    let (name, token) = match mode {
        Mode::Evasive => ("evasive", None),
        Mode::Fast => ("fast", None),
        Mode::Identify(t) => ("identify", Some(t.as_str())),
    };
    let id = crate::backend::ask(
        "identity.resolve",
        &Ask {
            mode: name,
            token,
            seed,
        },
    )
    .and_then(|a: Answer| {
        let clean = !a.user_agent.is_empty()
            && crate::backend::is_header_value(&a.user_agent)
            && a.headers.len() <= 32
            && a.headers.iter().all(|(k, v)| {
                crate::backend::is_header_name(k)
                    && crate::backend::is_header_value(v)
                    && !k.eq_ignore_ascii_case("user-agent")
                    && !NOT_AN_IDENTITY.contains(&k.to_ascii_lowercase().as_str())
            });
        let attributed = match token {
            Some(t) => a.headers.iter().any(|(k, v)| k == ATTRIBUTION && v == t),
            None => true,
        };
        if !(clean && attributed) {
            return None;
        }
        let headers = a
            .headers
            .into_iter()
            .map(|(k, v)| Some((interned(&k)?, v)))
            .collect::<Option<Vec<_>>>()?;
        Some(Identity {
            user_agent: a.user_agent,
            headers,
        })
    });
    let mut kept = kept.lock().ok()?;
    if kept.len() >= 4096 {
        kept.clear();
    }
    kept.insert(key, id.clone());
    id
}

/// The header carrying an `Identify` token.
const ATTRIBUTION: &str = "X-Bug-Bounty";

/// `name` as a static string. Header names come from a small set, so each is leaked
/// once and reused; past 256 different names, None.
fn interned(name: &str) -> Option<&'static str> {
    use std::collections::HashSet;
    use std::sync::Mutex;
    static NAMES: std::sync::OnceLock<Mutex<HashSet<&'static str>>> = std::sync::OnceLock::new();
    let mut names = NAMES
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(n) = names.get(name) {
        return Some(n);
    }
    if names.len() >= 256 {
        return None;
    }
    let n: &'static str = Box::leak(name.to_string().into_boxed_str());
    names.insert(n);
    Some(n)
}

/// One current desktop-Chrome identity with a coherent navigation header set.
fn chrome_desktop() -> Identity {
    Identity {
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
            .to_string(),
        headers: vec![
            (
                "Accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,\
                 image/avif,image/webp,image/apng,*/*;q=0.8,\
                 application/signed-exchange;v=b3;q=0.7"
                    .to_string(),
            ),
            ("Accept-Language", "en-US,en;q=0.9".to_string()),
            ("Accept-Encoding", "gzip, deflate, br, zstd".to_string()),
            (
                "sec-ch-ua",
                "\"Chromium\";v=\"138\", \"Google Chrome\";v=\"138\", \
                 \"Not)A;Brand\";v=\"99\""
                    .to_string(),
            ),
            ("sec-ch-ua-mobile", "?0".to_string()),
            ("sec-ch-ua-platform", "\"Windows\"".to_string()),
            ("Upgrade-Insecure-Requests", "1".to_string()),
            ("Sec-Fetch-Dest", "document".to_string()),
            ("Sec-Fetch-Mode", "navigate".to_string()),
            ("Sec-Fetch-Site", "none".to_string()),
            ("Sec-Fetch-User", "?1".to_string()),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_is_a_browser_not_a_scanner() {
        for mode in [Mode::Evasive, Mode::Fast] {
            let id = resolve(&mode, Some("example.com"));
            assert!(id.user_agent.starts_with("Mozilla/5.0"));
            // The engines' names, and the names they had before.
            for tell in [
                "plessor", "toolmark", "ambulo", "doorward", "cortex", "scout", "mach",
            ] {
                assert!(!id.user_agent.to_lowercase().contains(tell), "{tell}");
            }
            assert!(!id.user_agent.contains("clickswave"));
            assert!(!id.headers.is_empty());
        }
    }

    #[test]
    fn identify_advertises_the_token() {
        let id = resolve(&Mode::Identify("h1-handle".into()), None);
        assert!(
            id.headers
                .iter()
                .any(|(k, v)| *k == "X-Bug-Bounty" && v == "h1-handle")
        );
    }

    #[test]
    fn from_flags_maps_switch_to_mode() {
        assert!(matches!(Mode::from_flags(true, None), Mode::Evasive));
        assert!(matches!(Mode::from_flags(false, None), Mode::Fast));
        // An empty token is ignored (falls back to the evasive flag).
        assert!(matches!(
            Mode::from_flags(true, Some(String::new())),
            Mode::Evasive
        ));
        match Mode::from_flags(false, Some("h1".into())) {
            Mode::Identify(t) => assert_eq!(t, "h1"),
            other => panic!("identify token should win, got {other:?}"),
        }
    }

    #[test]
    fn baseline_does_not_rotate_by_seed() {
        // The open baseline is deterministic regardless of seed.
        let a = resolve(&Mode::Evasive, Some("a.com")).user_agent;
        let b = resolve(&Mode::Evasive, Some("b.com")).user_agent;
        assert_eq!(a, b);
    }
}

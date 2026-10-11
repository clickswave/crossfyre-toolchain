//! Outbound request identity: the User-Agent and browser hint headers the
//! engines present on the wire.
//!
//! ## Open baseline
//!
//! This public baseline returns a single, honest, current desktop-Chrome
//! identity with a coherent header set and performs **no rotation**. It exists so
//! the open toolchain presents a plausible, non-self-identifying client rather
//! than a scanner banner. The tuned profile catalogue and per-target rotation is
//! a private drop-in; keep these signatures stable so it stays a clean drop-in.
//!
//! Coherence is the whole point: bot-detection cross-checks the User-Agent
//! against the header set (and, with real fingerprint parity, the TLS/HTTP2
//! handshake), so the UA and the headers must always describe the *same* browser.

/// How the caller wants to present on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
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
pub fn resolve(mode: &Mode, _seed: Option<&str>) -> Identity {
    match mode {
        // The baseline has no catalogue, so every mode maps to the one honest
        // desktop-Chrome identity. `Identify` additionally advertises the token.
        Mode::Identify(token) => {
            let mut id = chrome_desktop();
            id.headers.push(("X-Bug-Bounty", token.clone()));
            id
        }
        _ => chrome_desktop(),
    }
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

//! Challenge / anti-bot awareness.
//!
//! Recognises when a response came from a WAF or anti-bot layer (a hard block,
//! an interactive JS/CAPTCHA/Turnstile challenge, or velocity throttling) rather
//! than the origin application, and recommends a reaction: proceed, back off and
//! retry (optionally rotating the outbound identity), escalate to the challenge
//! broker, or abort.
//!
//! This is the PUBLIC baseline. It recognises only the obvious, well-documented
//! signatures and reacts conservatively (no broker escalation). The tuned
//! signature set, edge scoring, and thresholds live in the pacing module:
//! challenge detection is adversarially sensitive, so a WAF vendor reading the
//! open toolchain must not be able to enumerate exactly what we key on.

/// Classification of an interfering response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Challenge {
    /// No anti-bot interference detected.
    None,
    /// An interactive JS / CAPTCHA / Turnstile challenge page.
    Interactive,
    /// A hard block or access-denied from the edge.
    Blocked,
    /// Rate limited (velocity throttle).
    RateLimited,
}

impl Challenge {
    /// True for anything other than [`Challenge::None`].
    pub fn is_challenge(self) -> bool {
        !matches!(self, Challenge::None)
    }

    /// A short stable label for logs / findings.
    pub fn label(self) -> &'static str {
        match self {
            Challenge::None => "none",
            Challenge::Interactive => "interactive_challenge",
            Challenge::Blocked => "blocked",
            Challenge::RateLimited => "rate_limited",
        }
    }
}

/// Recommended reaction to a detected challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reaction {
    /// Nothing to do; carry on.
    Proceed,
    /// Wait `delay_ms`, then retry. Rebuild the outbound identity first when
    /// `rotate_identity` is set (a fresh browser profile for the same target).
    Backoff {
        delay_ms: u64,
        rotate_identity: bool,
    },
    /// Escalate to the challenge broker (a headless browser mints clearance,
    /// whose cookie is handed back to the fast client). A paid, private-policy
    /// lever: the public baseline never returns this.
    Broker,
    /// Stop hitting this target for now.
    Abort,
}

/// Inspect a response for anti-bot interference.
///
/// `status` is the HTTP status; `header` looks a header value up by its
/// lowercased name; `body_prefix` is the first chunk of the body (a few KB is
/// plenty). The header lookup is a closure so callers need not build a map.
pub fn detect(
    status: u16,
    header: impl Fn(&str) -> Option<String>,
    body_prefix: &str,
) -> Challenge {
    // Velocity throttling is unambiguous from the status line.
    if status == 429 {
        return Challenge::RateLimited;
    }
    if let Some(c) = from_module(status, &header, body_prefix) {
        return c;
    }

    let body = body_prefix.to_ascii_lowercase();

    // Interactive challenge markers (the well-known public ones only).
    let interactive = body.contains("just a moment")
        || body.contains("/cdn-cgi/challenge-platform")
        || body.contains("challenge-platform")
        || body.contains("turnstile");
    if interactive && matches!(status, 200 | 403 | 429 | 503) {
        return Challenge::Interactive;
    }

    // Hard-block markers.
    let blocked = header("cf-mitigated").is_some()
        || body.contains("attention required")
        || body.contains("access denied")
        || body.contains("you have been blocked");
    if blocked && matches!(status, 403 | 406 | 503) {
        return Challenge::Blocked;
    }

    // A bare 403/503 from a known edge is suspicious but not conclusive; the
    // pacing module scores those. The baseline stays conservative.
    Challenge::None
}

/// Decide what to do about a challenge, given how many times we have already hit
/// one on this target (`attempt`, 0-based).
///
/// Baseline policy: backoff with identity rotation for the first tries, then give
/// up. The broker is never invoked here (it is a private, paid escalation).
pub fn react(challenge: Challenge, attempt: u32) -> Reaction {
    if challenge.is_challenge()
        && let Some(r) = react_from_module(challenge, attempt)
    {
        return r;
    }
    match challenge {
        Challenge::None => Reaction::Proceed,
        Challenge::RateLimited => {
            if attempt >= 4 {
                Reaction::Abort
            } else {
                Reaction::Backoff {
                    delay_ms: 2000u64 << attempt.min(4),
                    rotate_identity: false,
                }
            }
        }
        Challenge::Interactive | Challenge::Blocked => {
            if attempt >= 2 {
                Reaction::Abort
            } else {
                Reaction::Backoff {
                    delay_ms: 1500u64 << attempt.min(3),
                    rotate_identity: true,
                }
            }
        }
    }
}

/// What a module looks for in a response: header names, and strings in the
/// lowercased body.
#[derive(Clone)]
struct Looks {
    headers: Vec<String>,
    markers: Vec<String>,
}

/// The installed module's verdict. The module says once which headers and body
/// strings it reads; the body is searched for those here, and the module decides
/// from the status, those headers' values, which strings were found and the body's
/// trimmed length. None without a module or a readable answer.
fn from_module(
    status: u16,
    header: &impl Fn(&str) -> Option<String>,
    body_prefix: &str,
) -> Option<Challenge> {
    use std::collections::BTreeMap;
    #[derive(serde::Deserialize)]
    struct LooksAnswer {
        headers: Vec<String>,
        markers: Vec<String>,
    }
    #[derive(serde::Serialize)]
    struct Ask<'a> {
        status: u16,
        headers: BTreeMap<&'a str, String>,
        found: Vec<usize>,
        body_len: usize,
    }
    #[derive(serde::Deserialize)]
    struct Answer {
        challenge: String,
    }
    static LOOKS: std::sync::OnceLock<Option<Looks>> = std::sync::OnceLock::new();
    let looks = crate::backend::ask_once(&LOOKS, "challenge.markers", &(), |a: LooksAnswer| {
        let fits = a.headers.len() <= 32
            && a.markers.len() <= 64
            && a.headers.iter().all(|h| crate::backend::is_header_name(h))
            && a.markers.iter().all(|m| !m.is_empty() && m.len() <= 128);
        fits.then(|| Looks {
            headers: a.headers.iter().map(|h| h.to_ascii_lowercase()).collect(),
            markers: a.markers.iter().map(|m| m.to_ascii_lowercase()).collect(),
        })
    })?;
    let body = body_prefix.to_ascii_lowercase();
    let ask = Ask {
        status,
        headers: looks
            .headers
            .iter()
            .filter_map(|h| header(h).map(|v| (h.as_str(), v)))
            .collect(),
        found: (0..looks.markers.len())
            .filter(|&i| body.contains(looks.markers[i].as_str()))
            .collect(),
        body_len: body.trim().len(),
    };
    let a: Answer = crate::backend::ask("challenge.detect", &ask)?;
    [
        Challenge::None,
        Challenge::Interactive,
        Challenge::Blocked,
        Challenge::RateLimited,
    ]
    .into_iter()
    .find(|c| c.label() == a.challenge)
}

/// The most challenges one target may see before a module's reaction becomes
/// [`Reaction::Abort`], so no module can keep an engine retrying a target that
/// refuses it.
const MOST_ATTEMPTS: u32 = 8;

/// The longest backoff a module may ask for.
const LONGEST_BACKOFF_MS: u64 = 300_000;

/// The installed module's reaction, held to [`MOST_ATTEMPTS`] and
/// [`LONGEST_BACKOFF_MS`]. None without a module or a readable answer.
fn react_from_module(challenge: Challenge, attempt: u32) -> Option<Reaction> {
    #[derive(serde::Serialize)]
    struct Ask {
        challenge: &'static str,
        attempt: u32,
    }
    #[derive(serde::Deserialize)]
    struct Answer {
        reaction: String,
        #[serde(default)]
        delay_ms: u64,
        #[serde(default)]
        rotate_identity: bool,
    }
    if !crate::backend::installed() {
        return None;
    }
    if attempt >= MOST_ATTEMPTS {
        return Some(Reaction::Abort);
    }
    let a: Answer = crate::backend::ask(
        "challenge.react",
        &Ask {
            challenge: challenge.label(),
            attempt,
        },
    )?;
    match a.reaction.as_str() {
        "proceed" => Some(Reaction::Proceed),
        "backoff" => Some(Reaction::Backoff {
            delay_ms: a.delay_ms.min(LONGEST_BACKOFF_MS),
            rotate_identity: a.rotate_identity,
        }),
        "broker" => Some(Reaction::Broker),
        "abort" => Some(Reaction::Abort),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_headers(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn clean_response_is_none() {
        assert_eq!(
            detect(200, no_headers, "<html>hello</html>"),
            Challenge::None
        );
    }

    #[test]
    fn rate_limit_by_status() {
        assert_eq!(detect(429, no_headers, ""), Challenge::RateLimited);
    }

    #[test]
    fn interactive_challenge_body() {
        assert_eq!(
            detect(503, no_headers, "<title>Just a moment...</title>"),
            Challenge::Interactive
        );
    }

    #[test]
    fn blocked_by_header() {
        let h = |n: &str| (n == "cf-mitigated").then(|| "challenge".to_string());
        assert_eq!(detect(403, h, ""), Challenge::Blocked);
    }

    #[test]
    fn react_rotates_then_aborts() {
        assert!(matches!(
            react(Challenge::Blocked, 0),
            Reaction::Backoff {
                rotate_identity: true,
                ..
            }
        ));
        assert_eq!(react(Challenge::Blocked, 2), Reaction::Abort);
    }

    #[test]
    fn baseline_never_brokers() {
        for a in 0..8 {
            assert_ne!(react(Challenge::Interactive, a), Reaction::Broker);
            assert_ne!(react(Challenge::Blocked, a), Reaction::Broker);
        }
    }
}

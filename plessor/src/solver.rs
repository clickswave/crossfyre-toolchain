//! Challenge-solver client (FlareSolverr-compatible).
//!
//! Last-resort WAF evasion: when a target sits behind an interactive
//! CF/anti-bot challenge that fingerprint parity + backoff cannot clear, plessor
//! hands the URL to a self-hosted solver the OPERATOR runs (e.g. FlareSolverr),
//! which drives a real browser and returns a clearance cookie.
//!
//! Two hard rules from the egress model, both enforced here:
//!   1. The solver runs on the NODE (or the node's egress), so the clearance is
//!      minted from the USER's IP - never shared control-plane infra.
//!   2. `cf_clearance` is bound to IP + UA. If the node egresses through a proxy,
//!      the solver must use the SAME proxy, and plessor must present the SAME UA,
//!      or the cookie is rejected. We pass the node's `CROSSFYRE_EGRESS_PROXY` to
//!      the solver and return its UA for plessor to adopt.
//!
//! Configured with `CROSSFYRE_CHALLENGE_SOLVER` = the solver's `/v1` endpoint;
//! unset means no solver (plessor just reports the block). This is a niche,
//! best-effort last resort: origin discovery, fingerprint parity, and
//! residential egress clear the large majority of blocks without it.

use serde_json::json;

pub struct Solved {
    /// Ready-to-send `Cookie:` header value (`name=value; name=value`).
    pub cookie_header: String,
    /// The UA the solver's browser used. plessor must present the SAME UA or the
    /// cf_clearance (bound to UA + IP) is rejected.
    pub user_agent: Option<String>,
}

/// Whether a solver is configured.
pub fn configured() -> bool {
    std::env::var("CROSSFYRE_CHALLENGE_SOLVER")
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
}

/// Ask the configured solver to clear `target_url`. Returns the clearance cookies
/// + UA, or None if no solver is configured or it failed.
pub async fn solve(target_url: &str, timeout_ms: u64) -> Option<Solved> {
    let endpoint = std::env::var("CROSSFYRE_CHALLENGE_SOLVER")
        .ok()
        .filter(|s| !s.trim().is_empty())?;
    let egress_proxy = std::env::var("CROSSFYRE_EGRESS_PROXY")
        .ok()
        .filter(|s| !s.trim().is_empty());
    let max_timeout = timeout_ms.max(20_000);

    let mut body = json!({
        "cmd": "request.get",
        "url": target_url,
        "maxTimeout": max_timeout,
    });
    // Same egress as the scan, so the IP-bound clearance is valid for plessor.
    if let Some(px) = &egress_proxy {
        body["proxy"] = json!({ "url": px });
    }

    // A PLAIN reqwest client (no impersonation, and crucially NOT the transport
    // client, which would route this localhost control call through the egress
    // proxy). The solver endpoint is the operator's own service.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(max_timeout + 10_000))
        .build()
        .ok()?;
    let resp = client
        .post(endpoint.trim_end_matches('/'))
        .json(&body)
        .send()
        .await
        .ok()?;
    let v: serde_json::Value = resp.json().await.ok()?;
    if v["status"].as_str() != Some("ok") {
        return None;
    }
    let sol = v.get("solution")?;
    let ua = sol
        .get("userAgent")
        .and_then(|u| u.as_str())
        .map(|s| s.to_string());
    let cookies = sol.get("cookies")?.as_array()?;
    let mut parts = Vec::new();
    for c in cookies {
        if let (Some(n), Some(val)) = (
            c.get("name").and_then(|x| x.as_str()),
            c.get("value").and_then(|x| x.as_str()),
        ) {
            parts.push(format!("{n}={val}"));
        }
    }
    if parts.is_empty() {
        return None;
    }
    Some(Solved {
        cookie_header: parts.join("; "),
        user_agent: ua,
    })
}

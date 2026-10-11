//! Node-side OAST endpoint resolution. A vuln-scan op may carry an
//! `oast_endpoint_id` (the workspace's selected out-of-band server: "managed" or
//! "" for the managed pool, a self-hosted endpoint UUID, or "off" to disable OOB).
//! The node resolves it via the control plane into { domains, api_url } and hands
//! that to plessor, which registers/polls/decrypts directly (zero-knowledge).

use serde_json::{Value, json};

/// Resolve an OAST endpoint id into (callback_domains, poll_api_url). Returns
/// Ok(None) when OOB should be skipped ("off", or an endpoint with no usable
/// config). Errors are non-fatal to the caller: a scan still runs without OOB.
pub async fn resolve(
    http: &reqwest::Client,
    api_url: &str,
    node_api_key: &str,
    endpoint_id: &str,
) -> Result<Option<(Vec<String>, String)>, String> {
    let want = endpoint_id.trim();
    if want.eq_ignore_ascii_case("off") {
        return Ok(None);
    }
    let url = format!("{}/api/v1/oast/resolve", api_url.trim_end_matches('/'));
    let resp = http
        .post(&url)
        .json(&json!({ "api_key": node_api_key, "endpoint_id": want }))
        .send()
        .await
        .map_err(|e| format!("resolve request failed: {e}"))?;
    let body: Value = resp
        .json()
        .await
        .map_err(|e| format!("resolve decode failed: {e}"))?;

    let status = body["status"].as_i64().unwrap_or(0);
    if status != 200 {
        let msg = body["message"].as_str().unwrap_or("resolve rejected");
        return Err(format!("resolve {status}: {msg}"));
    }
    let d = &body["data"];
    let domains: Vec<String> = d["domains"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let poll_url = d["api_url"].as_str().unwrap_or("").to_string();
    if domains.is_empty() || poll_url.is_empty() {
        return Ok(None);
    }
    Ok(Some((domains, poll_url)))
}

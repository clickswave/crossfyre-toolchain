//! Full-capture config fetch + the manual-interception gate. In manual mode, on a device that allows
//! full requests, the tracer parks each request with the control plane (`intercept-hold`) and blocks
//! until a human forwards or drops it (`intercept-poll`), so the browser/app request does not
//! proceed until approved. Fail-open: any control-plane error, or no decision within [`WAIT`],
//! defaults to Forward so the user's traffic is never wedged.

use std::pin::Pin;
use std::time::Duration;

use tokio::time::Instant;

use cfx_capture::{EditedRequest, InterceptDecision, InterceptGate};
use serde_json::json;

/// Ask the control plane whether full capture / manual interception is on.
///
/// The shared-config fetch.
///
/// Transport only. The endpoint, request shape, parsing and fallback all live in
/// `cfx_capture::CaptureConfig`, shared with the desktop proxy, so the two clients
/// cannot disagree about what a setting means. They previously did: the caller
/// used to default `full_capture` to FALSE on a failed or partial response while
/// the documented default was true, so a control-plane blip quietly downgraded a
/// session to shape-only and the Requests tab just looked empty.
///
/// This returns the whole config rather than a tuple of the two fields anyone
/// happened to need first: a session carries bypass hosts now, and a tuple is how
/// the next setting gets silently dropped on one client.
///
/// `device_allows_full` is the device's own "Send full requests". It answers for holding
/// too: a held request is sent whole and can come back changed, and the switch's consent
/// sheet says so.
pub async fn fetch_capture_config(
    client: &reqwest::Client,
    api_url: &str,
    workflow_id: &str,
    token: &str,
    device_allows_full: bool,
) -> cfx_capture::CaptureConfig {
    let url = format!(
        "{}{}",
        api_url.trim_end_matches('/'),
        cfx_capture::config::CONFIG_PATH
    );
    // Report our own answer while asking for theirs, so the control plane can
    // explain an empty Requests tab instead of showing an unexplained blank.
    let body = cfx_capture::CaptureConfig::request_body_with_device(
        workflow_id,
        token,
        device_allows_full,
        device_allows_full,
    );
    match client.post(&url).json(&body).send().await {
        Ok(r) => match r.json::<serde_json::Value>().await {
            Ok(v) => cfx_capture::CaptureConfig::parse(&v),
            Err(e) => {
                log::warn!("capture config unreadable: {e}");
                cfx_capture::CaptureConfig::default()
            }
        },
        Err(e) => {
            log::warn!("capture config fetch failed: {e}");
            cfx_capture::CaptureConfig::default()
        }
    }
}

/// Build an EditedRequest from the poll payload's request fields (method/path/req_headers/req_body).
fn edited_from(d: &serde_json::Value) -> EditedRequest {
    let method = d
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("GET")
        .to_string();
    let path = d
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("/")
        .to_string();
    let headers = d
        .get("req_headers")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|h| {
                    let p = h.as_array()?;
                    Some((
                        p.first()?.as_str()?.to_string(),
                        p.get(1)?.as_str()?.to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default();
    let body = d
        .get("req_body")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .as_bytes()
        .to_vec();
    EditedRequest {
        method,
        path,
        headers,
        body,
    }
}

/// How long a request waits for a decision before it goes on unchanged.
pub const WAIT: Duration = Duration::from_secs(120);

/// The longest any one call to the control plane may take. Without a limit a call on a
/// connection that had gone quiet never returned, so a request could wait far past
/// [`WAIT`], and the control plane forgets a held request ten minutes after it was held.
const CALL: Duration = Duration::from_secs(10);

/// How often a held request asks whether it has been decided.
const POLL_EVERY: Duration = Duration::from_secs(1);

/// Parks each request with the control plane and sends on whatever is decided there.
///
/// It sends the whole request, values included, and may be told to send an edited one, so it
/// is installed only when the device allows full requests (`capture_cfg` in lib.rs).
pub struct HttpGate {
    pub client: reqwest::Client,
    pub api_url: String,
    pub workflow_id: String,
    pub token: String,
    /// How long each request waits for a decision: [`WAIT`].
    pub wait: Duration,
}

impl HttpGate {
    async fn decide_async(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> InterceptDecision {
        // One deadline for the whole wait, the hold included, however the calls go.
        let deadline = Instant::now() + self.wait;
        let left = || deadline.saturating_duration_since(Instant::now());
        let base = self.api_url.trim_end_matches('/');
        let hdr_json: Vec<[String; 2]> = headers
            .iter()
            .map(|(k, v)| [k.clone(), v.clone()])
            .collect();
        let hold = json!({
            "workflow_id": self.workflow_id,
            "token": self.token,
            "method": method,
            "url": url,
            "req_headers": hdr_json,
            "req_body": String::from_utf8_lossy(body),
            // This gate runs only on a device that allows holding, and the control plane
            // stores a hold only when the hold itself says so.
            "device_allows_hold": true,
        });
        let resp = self
            .client
            .post(format!("{base}/api/v1/web-trace/intercept-hold"))
            .json(&hold)
            .timeout(left().min(CALL))
            .send()
            .await;
        let id = match resp {
            Ok(r) => {
                let v: serde_json::Value = r.json().await.unwrap_or_default();
                v.get("data")
                    .and_then(|d| d.get("intercept_id"))
                    .and_then(|i| i.as_i64())
            }
            Err(e) => {
                log::warn!("intercept hold failed: {e}");
                None
            }
        };
        let Some(id) = id else {
            return InterceptDecision::Forward;
        }; // fail-open

        // Poll until a human decides, or the wait runs out (then fail-open to Forward).
        let poll =
            json!({ "workflow_id": self.workflow_id, "token": self.token, "intercept_id": id });
        loop {
            tokio::time::sleep(left().min(POLL_EVERY)).await;
            let rest = left();
            if rest.is_zero() {
                return InterceptDecision::Forward;
            }
            match self
                .client
                .post(format!("{base}/api/v1/web-trace/intercept-poll"))
                .json(&poll)
                .timeout(rest.min(CALL))
                .send()
                .await
            {
                Ok(r) => {
                    let v: serde_json::Value = r.json().await.unwrap_or_default();
                    let d = v.get("data").cloned().unwrap_or_default();
                    let decision = d
                        .get("decision")
                        .and_then(|s| s.as_str())
                        .unwrap_or("pending");
                    match decision {
                        "drop" => return InterceptDecision::Drop,
                        "forward" => {
                            // If the operator edited the held request, forward THAT; else forward as-is.
                            if d.get("modified").and_then(|b| b.as_bool()).unwrap_or(false) {
                                return InterceptDecision::ForwardModified(edited_from(&d));
                            }
                            return InterceptDecision::Forward;
                        }
                        _ => continue,
                    }
                }
                Err(_) => continue,
            }
        }
    }
}

impl InterceptGate for HttpGate {
    fn decide<'a>(
        &'a self,
        method: &'a str,
        url: &'a str,
        headers: &'a [(String, String)],
        body: &'a [u8],
    ) -> Pin<Box<dyn std::future::Future<Output = InterceptDecision> + Send + 'a>> {
        Box::pin(self.decide_async(method, url, headers, body))
    }
}

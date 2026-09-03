//! Full-capture config fetch + the manual-interception gate. In manual mode the tracer parks each
//! request with the control plane (`intercept-hold`) and blocks until a human forwards or drops it
//! (`intercept-poll`), so the browser/app request does not proceed until approved. Fail-open: any
//! control-plane error or a long wait defaults to Forward so the user's traffic is never wedged.

use std::pin::Pin;
use std::time::Duration;

use cfx_capture::{EditedRequest, InterceptDecision, InterceptGate};
use serde_json::json;

/// Ask the control plane whether full capture / manual interception is on.
///
/// Transport only. The endpoint, request shape, parsing and fallback all live in
/// `cfx_capture::CaptureConfig`, shared with the desktop proxy, so the two clients
/// cannot disagree about what a setting means. They previously did: this function
/// used to default `full_capture` to FALSE on a failed or partial response while
/// the documented default was true, so a control-plane blip quietly downgraded a
/// session to shape-only and the Requests tab just looked empty.
pub async fn fetch_config(
    client: &reqwest::Client,
    api_url: &str,
    workflow_id: &str,
    token: &str,
) -> (bool, String) {
    let cfg = fetch_capture_config(client, api_url, workflow_id, token).await;
    (cfg.full_capture, cfg.intercept_mode)
}

/// The shared-config fetch. Prefer this over [`fetch_config`], which exists only
/// so the existing tuple call sites keep compiling.
pub async fn fetch_capture_config(
    client: &reqwest::Client,
    api_url: &str,
    workflow_id: &str,
    token: &str,
) -> cfx_capture::CaptureConfig {
    let url = format!(
        "{}{}",
        api_url.trim_end_matches('/'),
        cfx_capture::config::CONFIG_PATH
    );
    let body = cfx_capture::CaptureConfig::request_body(workflow_id, token);
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

pub struct HttpGate {
    pub client: reqwest::Client,
    pub api_url: String,
    pub workflow_id: String,
    pub token: String,
}

impl HttpGate {
    async fn decide_async(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> InterceptDecision {
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
        });
        let resp = self
            .client
            .post(format!("{base}/api/v1/web-trace/intercept-hold"))
            .json(&hold)
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

        // Poll until a human decides, or ~2 min elapses (then fail-open to Forward).
        let poll =
            json!({ "workflow_id": self.workflow_id, "token": self.token, "intercept_id": id });
        for _ in 0..120 {
            tokio::time::sleep(Duration::from_secs(1)).await;
            match self
                .client
                .post(format!("{base}/api/v1/web-trace/intercept-poll"))
                .json(&poll)
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
        InterceptDecision::Forward
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

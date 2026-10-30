//! HTTPS to the Cloud API: one `POST` per route, the key in a header, and nothing
//! followed.
//!
//! Redirects are off, so the key goes to the origin it was configured with and nowhere
//! else. The answer is read up to a fixed size, and its call id (the platform's record
//! of the request) is kept so the audit line can be matched to it.

use super::file::Key;
use crate::untrusted;
use cfx_cloud_wire::{self as wire, Envelope, header};
use serde_json::Value;
use std::time::Duration;

/// An answer larger than this is not read.
const ANSWER_MAX: usize = 4 * 1024 * 1024;
/// A route's own time limit. `approvals/wait` gets its hold on top.
pub(crate) const TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) struct Client {
    http: reqwest::Client,
    base: String,
    key: Key,
}

/// Who is calling, for the headers the platform records.
pub(crate) struct Meta<'a> {
    pub tool: &'a str,
    pub client: &'a str,
    pub session: &'a str,
    pub local_scope: &'a str,
}

/// What came back, read and parsed.
#[derive(Debug)]
pub(crate) struct Answer {
    pub status: u16,
    pub envelope: Envelope<Value>,
    pub call_id: Option<String>,
    pub retry_after: Option<u64>,
}

#[derive(Debug)]
pub(crate) enum Failure {
    /// Nothing usable came back: no connection, a timeout, a reset.
    Network(String),
    /// An answer that is not the API's envelope, such as a proxy's error page.
    Unreadable { status: u16, why: String },
}

impl Failure {
    pub(crate) fn describe(&self) -> String {
        match self {
            Failure::Network(why) => why.clone(),
            Failure::Unreadable { status, why } => format!("HTTP {status}: {why}"),
        }
    }

    /// Worth one more try: the request may never have arrived.
    pub(crate) fn transient(&self) -> bool {
        match self {
            Failure::Network(_) => true,
            Failure::Unreadable { status, .. } => matches!(status, 502..=504),
        }
    }
}

/// A header value as the platform will store it: printable ASCII, capped.
fn header_value(s: &str) -> reqwest::header::HeaderValue {
    let v: String = untrusted::clean(s, header::VALUE_MAX)
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .collect();
    reqwest::header::HeaderValue::from_str(&v)
        .unwrap_or_else(|_| reqwest::header::HeaderValue::from_static("unknown"))
}

/// The call id, kept only if it looks like one.
fn call_id(v: Option<&reqwest::header::HeaderValue>) -> Option<String> {
    let s = v?.to_str().ok()?;
    let ok = !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    ok.then(|| s.to_string())
}

impl Client {
    pub(crate) fn new(api_url: &str, key: Key, version: &str) -> Result<Self, String> {
        let loopback = transport::Url::parse(api_url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
            .is_some_and(|h| matches!(h.as_str(), "localhost" | "127.0.0.1" | "[::1]"));
        let mut b = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(format!("crossfyre-mcp/{version}"))
            .timeout(TIMEOUT)
            .connect_timeout(Duration::from_secs(10));
        if loopback {
            // A proxy set for the internet has no business seeing a key for this machine.
            b = b.no_proxy();
        }
        let http = b
            .build()
            .map_err(|e| format!("could not build the Cloud client: {e}"))?;
        Ok(Client {
            http,
            base: format!("{}{}", api_url.trim_end_matches('/'), wire::PATH),
            key,
        })
    }

    pub(crate) async fn post(
        &self,
        route: &str,
        meta: &Meta<'_>,
        body: &Value,
        hold: Duration,
    ) -> Result<Answer, Failure> {
        let url = format!("{}{route}", self.base);
        let auth = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", self.key.expose()))
            .map_err(|_| Failure::Network("the key cannot be sent as a header".into()))?;
        let mut auth = auth;
        auth.set_sensitive(true);
        let resp = self
            .http
            .post(&url)
            .timeout(TIMEOUT + hold)
            .header(reqwest::header::AUTHORIZATION, auth)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(header::CLIENT, header_value(meta.client))
            .header(header::SESSION, header_value(meta.session))
            .header(header::TOOL, header_value(meta.tool))
            .header(header::LOCAL_SCOPE, header_value(meta.local_scope))
            .body(body.to_string())
            .send()
            .await
            .map_err(|e| Failure::Network(describe(&e)))?;
        let status = resp.status().as_u16();
        let call_id = call_id(resp.headers().get(header::CALL_ID));
        let retry_after = resp
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(|s| s.min(3600));
        let mut resp = resp;
        let mut bytes: Vec<u8> = Vec::new();
        loop {
            match resp.chunk().await {
                Ok(Some(c)) => {
                    if bytes.len() + c.len() > ANSWER_MAX {
                        return Err(Failure::Unreadable {
                            status,
                            why: "the answer was larger than 4 MB".into(),
                        });
                    }
                    bytes.extend_from_slice(&c);
                }
                Ok(None) => break,
                Err(e) => return Err(Failure::Network(describe(&e))),
            }
        }
        let envelope: Envelope<Value> =
            serde_json::from_slice(&bytes).map_err(|_| Failure::Unreadable {
                status,
                why: "the answer is not the Cloud API's JSON".into(),
            })?;
        Ok(Answer {
            status,
            envelope,
            call_id,
            retry_after,
        })
    }
}

/// A transport error in a sentence, without the request it was about.
fn describe(e: &reqwest::Error) -> String {
    let what = if e.is_timeout() {
        "timed out"
    } else if e.is_connect() {
        "could not connect"
    } else if e.is_body() || e.is_decode() {
        "the answer was cut off"
    } else {
        "the request failed"
    };
    let host = e
        .url()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_default();
    if host.is_empty() {
        what.to_string()
    } else {
        format!("{what} ({})", untrusted::clean(&host, 200))
    }
}

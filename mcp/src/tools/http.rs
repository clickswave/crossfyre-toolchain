//! `send_http_request`: one request, sent from here, the way a person would replay it.
//!
//! The connection is pinned to the address the guard cleared, so the name cannot be
//! resolved again to somewhere else between the check and the connect. Redirects are
//! followed only when asked, by this code rather than the client, so every hop goes
//! through the guard before anything is sent to it.

use super::{in_range, parse_args, result_size};
use crate::confirm::WriteAsk;
use crate::core::{CallNote, Clearance, Done, Intent, Mcp, Reason, Refusal, TrafficRequest};
use crate::guard;
use crate::peer::ClientPeer;
use crate::redact;
use crate::untrusted::{self, RESULT_CAP};
use cfx_scope::Point;
use regex::Regex;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

static TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,16}$").expect("method pattern"));

/// Headers the client sets from the request itself, or that change how the
/// connection is used. Taking them from a model would let it frame a second request
/// inside the first.
fn forbidden_header(name: &str) -> bool {
    matches!(
        name,
        "content-length" | "transfer-encoding" | "connection" | "upgrade" | "te" | "trailer"
    ) || name.starts_with("proxy-")
}

/// Whether a header goes with a redirect to another origin. Credentials do not:
/// the standard ones, and anything else named like one.
fn crosses_origins(name: &str) -> bool {
    !matches!(
        name,
        "authorization" | "cookie" | "proxy-authorization" | "host"
    ) && !redact::sensitive_name(name)
}

const HEADER_VALUE_MAX: usize = 1024;
const HEADERS_TOTAL_MAX: usize = 8 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    method: String,
    url: String,
    #[serde(default)]
    headers: Option<Map<String, Value>>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    follow_redirects: Option<bool>,
    #[serde(default)]
    max_redirects: Option<u64>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_body_bytes: Option<u64>,
}

fn safe(method: &str) -> bool {
    matches!(method, "GET" | "HEAD" | "OPTIONS")
}

struct Sent {
    status: u16,
    headers: Vec<(String, String)>,
    location: Option<String>,
    body: Vec<u8>,
    truncated: bool,
    headers_ms: u64,
}

struct Request<'a> {
    method: &'a str,
    url: &'a str,
    headers: &'a [(String, String)],
    body: Option<&'a str>,
    timeout: Duration,
    max_body: usize,
    user_agent: &'a str,
}

/// What went wrong, from the kind of error only. The error's own text carries the
/// request URL, which after a redirect is whatever the target wrote.
fn failure(e: &transport::Error) -> &'static str {
    if e.is_timeout() {
        "timed out"
    } else if e.is_connect() {
        "could not connect"
    } else {
        "failed"
    }
}

/// Send one request to a cleared destination, pinned to the address it was cleared at.
/// An error is the end of a sentence that starts "The request to <origin>".
async fn send_once(cleared: &Clearance, r: Request<'_>) -> Result<Sent, String> {
    let c = &cleared.cleared[0];
    let resolve = match c.dest.ip {
        Some(_) => Vec::new(),
        None => vec![(c.dest.host.clone(), c.addrs[0])],
    };
    let client = transport::build_client(transport::ClientConfig {
        timeout: Some(r.timeout),
        redirect: transport::Redirect::None,
        accept_invalid_certs: true,
        cookie_store: false,
        user_agent: Some(r.user_agent.to_string()),
        resolve,
        ..Default::default()
    })
    .map_err(|_| "was not sent: no client could be built".to_string())?;
    let method = transport::Method::from_bytes(r.method.as_bytes())
        .map_err(|_| "was not sent: the method is not valid".to_string())?;
    let mut rb = client.request(method, r.url);
    for (k, v) in r.headers {
        rb = rb.header(k.as_str(), v.as_str());
    }
    if let Some(b) = r.body {
        rb = rb.body(b.to_string());
    }
    let t0 = Instant::now();
    let mut resp = rb.send().await.map_err(|e| failure(&e).to_string())?;
    let headers_ms = t0.elapsed().as_millis() as u64;
    let status = resp.status().as_u16();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    let location = headers
        .iter()
        .find(|(k, _)| k == "location")
        .map(|(_, v)| v.clone());
    let mut body = Vec::new();
    let mut truncated = false;
    while let Ok(Some(chunk)) = resp.chunk().await {
        let room = r.max_body + 1 - body.len();
        body.extend_from_slice(&chunk[..chunk.len().min(room)]);
        if body.len() > r.max_body {
            body.truncate(r.max_body);
            truncated = true;
            break;
        }
    }
    Ok(Sent {
        status,
        headers,
        location,
        body,
        truncated,
        headers_ms,
    })
}

pub(crate) async fn run(
    mcp: &Mcp,
    args: &Value,
    peer: &dyn ClientPeer,
    ct: &CancellationToken,
    note: &mut CallNote,
) -> Result<Done, Refusal> {
    let a: Args = parse_args(args)?;
    if !TOKEN.is_match(&a.method) {
        return Err(Refusal::invalid(
            "method must be an HTTP method name of at most 16 characters",
        ));
    }
    let method = a.method.to_ascii_uppercase();
    let follow = a.follow_redirects.unwrap_or(false);
    let max_redirects = in_range("max_redirects", a.max_redirects.unwrap_or(5), 1, 5)? as usize;
    let timeout = in_range("timeout_seconds", a.timeout_seconds.unwrap_or(20), 1, 60)?;
    let max_body = in_range(
        "max_body_bytes",
        a.max_body_bytes.unwrap_or(8192),
        1,
        32_768,
    )? as usize;
    if a.body.as_ref().is_some_and(|b| b.len() > 64 * 1024) {
        return Err(Refusal::invalid("body is limited to 64 KiB"));
    }
    let dest = guard::parse_target(&a.url).map_err(|e| Refusal::invalid(format!("url: {e}")))?;

    let mut headers: Vec<(String, String)> = Vec::new();
    let mut host_header: Option<String> = None;
    if let Some(h) = &a.headers {
        if h.len() > 50 {
            return Err(Refusal::invalid("headers holds at most 50 entries"));
        }
        let mut seen = std::collections::HashSet::new();
        for (k, v) in h {
            let name = k.trim().to_ascii_lowercase();
            // `Host` and `host` are two keys to JSON and one header to HTTP. Both
            // would be sent, and the target, not this server, picks which counts.
            if !seen.insert(name.clone()) {
                return Err(Refusal::invalid(format!(
                    "the {:?} header is given more than once; give each header once",
                    untrusted::clean(&name, 64)
                )));
            }
            let Some(value) = v.as_str() else {
                return Err(Refusal::invalid("every header value must be a string"));
            };
            if value.len() > 8192 {
                return Err(Refusal::invalid("a header value is limited to 8 KB"));
            }
            if transport::HeaderName::from_bytes(name.as_bytes()).is_err()
                || transport::HeaderValue::from_str(value).is_err()
            {
                return Err(Refusal::invalid(format!(
                    "{:?} is not a valid header",
                    untrusted::clean(k, 64)
                )));
            }
            if forbidden_header(&name) {
                return Err(Refusal::invalid(format!(
                    "the {name} header is set by the client and cannot be given"
                )));
            }
            if name == "host" {
                host_header = Some(value.to_string());
            }
            headers.push((name, value.to_string()));
        }
    }

    let intent = if safe(&method) {
        Intent::Read
    } else {
        Intent::Write
    };
    let pending = mcp
        .precheck(TrafficRequest {
            tool: "send_http_request",
            dests: vec![dest.clone()],
            intent,
            point: Point::Repeater,
            pace: true,
            scan_start: false,
        })
        .await?;
    // A Host header names a destination too. A virtual host the file does not list is
    // somebody else's site on a shared address.
    if let Some(h) = &host_header {
        let hd = guard::parse_target(&format!("{}://{}", dest.scheme, h.trim()))
            .map_err(|e| Refusal::invalid(format!("Host header: {e}")))?;
        let port = if h.contains(':') { hd.port } else { dest.port };
        if !mcp.guard.admit(
            &hd.host,
            port,
            Point::Repeater,
            Some("crossfyre mcp send_http_request Host header"),
        ) {
            return Err(Refusal::new(
                Reason::OutOfScope,
                format!(
                    "Out of scope: the Host header names {}:{port}, which the scope file does \
                     not list. Nothing was sent.",
                    untrusted::clean(&hd.host, 200)
                ),
            )
            .with_refused(vec![crate::core::RefusedDest {
                host: untrusted::clean(&hd.host, 200),
                port,
                at: "host_header",
            }]));
        }
    }
    let write = (intent == Intent::Write).then(|| WriteAsk {
        remember: Some(dest.key()),
        message: format!(
            "send_http_request will send a {method} request to {}. Methods other than GET, \
             HEAD and OPTIONS can change or destroy data. Allow them to {} for the rest of this \
             session?",
            untrusted::clean(&dest.origin(), 200),
            untrusted::clean(&dest.key(), 200)
        ),
    });
    let mut clearance = mcp.confirm(pending, peer, write, note, ct).await?;

    let user_agent = format!("crossfyre/{}", mcp.settings.version);
    let started = Instant::now();
    let mut current = dest.clone();
    let mut method = method;
    let mut body = a.body.clone();
    let mut hops: Vec<Value> = Vec::new();
    let mut refused_hop: Option<(String, &'static str)> = None;
    let redact = mcp.settings.redact;
    let shown_url = |u: &str| {
        let u = untrusted::clean(u, 300);
        if redact { redact::redact_url(&u) } else { u }
    };
    let cancelled = || {
        Refusal::new(
            Reason::Cancelled,
            "The call was cancelled before it finished.",
        )
    };
    let sent = loop {
        let request = Request {
            method: &method,
            url: &current.url,
            headers: &headers,
            body: body.as_deref(),
            timeout: Duration::from_secs(timeout),
            max_body,
            user_agent: &user_agent,
        };
        let outcome = tokio::select! {
            r = send_once(&clearance, request) => r,
            _ = ct.cancelled() => return Err(cancelled()),
        };
        let sent = match outcome {
            Ok(s) => s,
            Err(kind) if hops.is_empty() => {
                return Err(Refusal::new(
                    Reason::RequestFailed,
                    format!(
                        "The request to {} {kind}.",
                        untrusted::clean(&dest.origin(), 200)
                    ),
                ));
            }
            // The URL that failed came from a redirect, so it goes back as target data.
            Err(kind) => {
                return Err(Refusal::new(
                    Reason::RequestFailed,
                    format!(
                        "The request {kind} after {} redirect(s); the URL it was sent to is \
                         under target_data.",
                        hops.len()
                    ),
                )
                .with_detail(json!({"target_data": {
                    "untrusted": true,
                    "failed_url": shown_url(&current.url),
                    "redirects": hops,
                }})));
            }
        };
        let redirect = matches!(sent.status, 301 | 302 | 303 | 307 | 308);
        if !(follow && redirect && hops.len() < max_redirects) {
            break sent;
        }
        let Some(loc) = sent.location.clone() else {
            break sent;
        };
        let shown_loc = shown_url(&loc);
        let next = transport::Url::parse(&current.url)
            .ok()
            .and_then(|base| base.join(&loc).ok())
            .ok_or("not a URL".to_string())
            .and_then(|u| guard::dest_from_url(&u));
        let next = match next {
            Ok(n) => n,
            Err(_) => {
                refused_hop = Some((shown_loc, "invalid_arguments"));
                break sent;
            }
        };
        // A 301, 302 or 303 after a write turns into a GET with no body, as browsers do.
        if matches!(sent.status, 301..=303) && !safe(&method) {
            method = "GET".into();
            body = None;
        }
        if next.origin() != current.origin() {
            headers.retain(|(k, _)| crosses_origins(k));
        }
        let write = (!safe(&method) && next.key() != current.key()).then(|| WriteAsk {
            remember: Some(next.key()),
            message: format!(
                "A redirect asks to send the {method} request on to {}. Allow write methods to \
                 {} for the rest of this session?",
                untrusted::clean(&next.origin(), 200),
                untrusted::clean(&next.key(), 200)
            ),
        });
        match mcp.clear_hop(next.clone(), peer, write, ct).await {
            Ok(c) => {
                hops.push(json!({"status": sent.status, "location": shown_loc}));
                clearance = c;
                current = next;
            }
            Err(r) => {
                note.refused.extend(r.refused.iter().cloned());
                refused_hop = Some((shown_loc, r.reason.as_str()));
                break sent;
            }
        }
    };
    let total_ms = started.elapsed().as_millis() as u64;

    let mut header_pairs = Vec::new();
    let mut header_bytes = 0usize;
    let mut truncated = sent.truncated;
    for (k, v) in &sent.headers {
        let (v, cut) = untrusted::sanitize(v, HEADER_VALUE_MAX);
        truncated |= cut;
        let v = if redact {
            redact::redact_header(k, &v)
        } else {
            v
        };
        header_bytes += k.len() + v.len();
        if header_bytes > HEADERS_TOTAL_MAX {
            truncated = true;
            break;
        }
        header_pairs.push(json!([k, v]));
    }
    let content_type = sent
        .headers
        .iter()
        .find(|(k, _)| k == "content-type")
        .map(|(_, v)| untrusted::clean(v, 200));
    let body_text = String::from_utf8_lossy(&sent.body);
    let (body_text, cut) = untrusted::sanitize(&body_text, max_body);
    truncated |= cut;
    let mut body_text = if redact {
        redact::redact_text(&body_text)
    } else {
        body_text
    };

    let mut target_data = json!({
        "untrusted": true,
        "headers": header_pairs,
        "content_type": content_type,
        "body": body_text,
        "body_bytes_read": sent.body.len(),
        "redirects": hops,
        "truncated": truncated,
    });
    let mut value = json!({
        "status": sent.status,
        "timing_ms": {"headers": sent.headers_ms, "total": total_ms},
        "redirect_count": hops.len(),
    });
    if let Some((loc, reason)) = &refused_hop {
        value["redirect_refused"] = json!({"reason": reason});
        target_data["refused_location"] = json!(loc);
    }
    value["target_data"] = target_data;
    // The origin asked for, not the one a redirect ended on: under a wildcard entry
    // the target picks that host name, and this line sits outside target_data.
    let summary = format!(
        "{} {} answered HTTP {} in {} ms{}{}.",
        method,
        untrusted::clean(&dest.origin(), 200),
        sent.status,
        total_ms,
        match hops.len() {
            0 => String::new(),
            n => format!(" after {n} redirect(s)"),
        },
        match &refused_hop {
            Some((_, r)) => format!("; a redirect was not followed ({r})"),
            None => String::new(),
        }
    );
    // Escaping can make a body longer as JSON than as text; shorten until it fits.
    while result_size(&summary, &value) > RESULT_CAP && !body_text.is_empty() {
        body_text = untrusted::cap_bytes(&body_text, body_text.len() / 2).0;
        value["target_data"]["body"] = json!(body_text);
        value["target_data"]["truncated"] = json!(true);
    }
    note.result = Some(json!({"status": sent.status, "redirects": hops.len()}));
    Ok(Done { value, summary })
}

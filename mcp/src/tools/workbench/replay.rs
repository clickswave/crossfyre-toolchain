//! `workbench_replay`: a stored request sent again through the Workbench, changed only
//! by the edits named.
//!
//! The send has to pass this server's checks first: the scope file, the addresses the
//! name resolves to, the Host header, the write rules and the person's confirmation.
//! The Workbench then checks the open project's scope, dials only one of the addresses
//! cleared here that its own lookup also gives, and records the send in the project.

use super::{
    EXCHANGE_TEXTS, Open, ask, bridge_refusal, fit, parse_handle, read_exchange, route, shown_body,
    shown_headers,
};
use crate::confirm::{AskKind, WriteAsk};
use crate::core::{CallNote, Done, Intent, Mcp, Reason, Refusal, RefusedDest, TrafficRequest};
use crate::peer::ClientPeer;
use crate::tools::overrides::{self, Asked, Via};
use crate::tools::parse_args;
use crate::{guard, untrusted};
use cfx_bridge::{
    Call, EDIT_ENTRIES_MAX, Edits, ErrorCode, ExchangeResult, McpRef, Origin, PINS_MAX, Part,
    ReplayParams, ReplayResult,
};
use cfx_scope::Point;
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// How long a replay waits for the Workbench: the send itself, then recording it.
const REPLAY_WAIT: Duration = Duration::from_secs(45);

/// The members `edits` may have.
const EDIT_FIELDS: [&str; 6] = ["path", "query", "headers", "form", "json", "body"];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    exchange: String,
    #[serde(default)]
    edits: Option<Value>,
    #[serde(default)]
    max_body_bytes: Option<u64>,
}

/// GET, HEAD and OPTIONS read. Anything else can change or destroy data.
fn safe(method: &str) -> bool {
    matches!(method, "GET" | "HEAD" | "OPTIONS")
}

/// What one name holds after the edits: an edit's value in place of the first, the
/// rest as captured, and nothing after a `null`.
fn after_edit(captured: Vec<String>, edited: Option<Option<&str>>) -> Vec<String> {
    match edited {
        None => captured,
        Some(None) => Vec::new(),
        Some(Some(v)) => std::iter::once(v.to_string())
            .chain(captured.into_iter().skip(1))
            .collect(),
    }
}

/// What the request as it will be sent asks for by override, when that is not a read:
/// a GET carrying `X-HTTP-Method-Override: DELETE` or `_method=DELETE`. Only a replaced
/// body is read, since the captured one is not fetched for this.
///
/// A header or query name is taken however it is spelt, and an edit stands in for the
/// captured values of the name it gives, the way the Workbench applies it.
fn overriding_write(stored: &ExchangeResult, edits: &Edits) -> Option<Asked> {
    /// Each name `is` accepts, once, in the order first seen.
    fn names<'a>(seen: impl Iterator<Item = &'a str>, is: impl Fn(&str) -> bool) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for n in seen.filter(|n| is(n)) {
            if !out.iter().any(|o| o.eq_ignore_ascii_case(n.trim())) {
                out.push(n.trim().to_string());
            }
        }
        out
    }
    fn edited<'a>(pairs: &'a cfx_bridge::Pairs, name: &str) -> Option<Option<&'a str>> {
        pairs
            .iter()
            .find(|(k, _)| k.trim().eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    }
    let mut asked: Vec<Asked> = Vec::new();
    let captured_headers = stored.req_headers.as_deref().unwrap_or(&[]);
    let header_names = names(
        captured_headers
            .iter()
            .map(|(k, _)| k.as_str())
            .chain(edits.headers.iter().map(|(k, _)| k)),
        |n| overrides::header(n).is_some(),
    );
    for name in header_names {
        let Some(h) = overrides::header(&name) else {
            continue;
        };
        let captured: Vec<String> = captured_headers
            .iter()
            .filter(|(k, _)| k.trim().eq_ignore_ascii_case(&name))
            .map(|(_, v)| v.clone())
            .collect();
        for v in after_edit(captured, edited(&edits.headers, &name)) {
            asked.push(Asked::new(Via::Header(h), Some(&v)));
        }
    }
    let query = match &edits.path {
        Some(p) => overrides::in_query(p),
        None => overrides::in_query(&stored.url),
    };
    let query_names = names(
        query
            .iter()
            .map(|(k, _)| k.as_str())
            .chain(edits.query.iter().map(|(k, _)| k)),
        overrides::is_field,
    );
    for name in query_names {
        let captured: Vec<String> = query
            .iter()
            .filter(|(k, _)| k.trim().eq_ignore_ascii_case(&name))
            .map(|(_, v)| v.clone())
            .collect();
        for v in after_edit(captured, edited(&edits.query, &name)) {
            asked.push(Asked::new(Via::Query, Some(&v)));
        }
    }
    for (k, v) in edits.form.iter() {
        if let Some(v) = v
            && overrides::is_field(k)
        {
            asked.push(Asked::new(Via::Field, Some(v)));
        }
    }
    if let Some(j) = &edits.json {
        for (k, v) in j {
            if !overrides::is_field(k) {
                continue;
            }
            match v {
                Value::Null => {}
                Value::String(s) => asked.push(Asked::new(Via::Field, Some(s))),
                _ => asked.push(Asked::new(Via::Body, None)),
            }
        }
    }
    if let Some(b) = edits.body.as_deref() {
        asked.extend(overrides::in_body(b));
    }
    overrides::first_write(asked)
}

fn parse_edits(v: Option<Value>) -> Result<Edits, Refusal> {
    let v = match v {
        None | Some(Value::Null) => return Ok(Edits::default()),
        Some(Value::Object(o)) => o,
        Some(_) => return Err(Refusal::invalid("edits must be a JSON object")),
    };
    if let Some(k) = v.keys().find(|k| !EDIT_FIELDS.contains(&k.as_str())) {
        return Err(Refusal::invalid(format!(
            "edits has no member {:?}; it takes {}",
            untrusted::clean(k, 40),
            EDIT_FIELDS.join(", ")
        )));
    }
    let edits: Edits = serde_json::from_value(Value::Object(v)).map_err(|e| {
        Refusal::invalid(format!("edits: {}", untrusted::clean(&e.to_string(), 300)))
    })?;
    edits
        .validate()
        .map_err(|e| Refusal::invalid(format!("edits: {}", untrusted::clean(&e, 300))))?;
    Ok(edits)
}

pub(crate) async fn run(
    mcp: &Mcp,
    args: &Value,
    peer: &dyn ClientPeer,
    ct: &CancellationToken,
    note: &mut CallNote,
) -> Result<Done, Refusal> {
    let a: Args = parse_args(args)?;
    let h = parse_handle(&a.exchange)?;
    let max = crate::tools::in_range(
        "max_body_bytes",
        a.max_body_bytes.unwrap_or(8192),
        1,
        32_768,
    )? as u32;
    let mut edits = parse_edits(a.edits)?;

    let o = route(mcp, "workbench_replay", None, Some(h.project)).await?;
    note.workbench = Some(o.audit());
    // The request as it was captured, without its body: where it goes and how.
    let stored = read_exchange(&o, h.id, vec![Part::Request], 0, ct).await?;
    let dest = guard::parse_target(&stored.url).map_err(|e| {
        Refusal::invalid(format!(
            "this exchange's URL cannot be replayed: {}",
            untrusted::clean(&e, 200)
        ))
    })?;
    let method = stored.method.to_ascii_uppercase();
    let stored_hosts: Vec<String> = stored
        .req_headers
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .filter(|(k, _)| k.trim().eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.clone())
        .collect();
    let edited_host = edits
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.map(str::to_string));
    let host_headers = sent_hosts(&stored_hosts, edited_host);

    // The method cannot be edited, but a framework can be asked to act as if it were.
    // A GET that asks for DELETE that way is a write here too.
    let overridden = if safe(&method) {
        overriding_write(&stored, &edits)
    } else {
        None
    };
    let intent = if safe(&method) && overridden.is_none() {
        Intent::Read
    } else {
        Intent::Write
    };
    let pending = mcp
        .precheck(TrafficRequest {
            tool: "workbench_replay",
            dests: vec![dest.clone()],
            intent,
            point: Point::Repeater,
            pace: true,
            scan_start: false,
        })
        .await?;
    // A Host header names a destination too. A virtual host the file does not list is
    // somebody else's site on a shared address. Every one the request will carry is
    // checked: a project with no scope admits whatever the Workbench is asked about, so
    // a second Host header nobody looked at here would go out unchecked.
    //
    // The Workbench still dials the captured host, so behind a front end that routes by
    // Host, a name the request was not captured with gets the captured session. That
    // takes a yes, even for a read.
    //
    // "Another name" is decided on the text that goes out, because the Workbench sends
    // the value as written and a front end routes on that text, not on what a URL parser
    // would make of it. Only a plain name equal to the URL's host passes, or one the
    // browser sent for this request through the proxy. A request the Workbench or an
    // agent sent carries whatever Host it was given, so its Host vouches for nothing.
    let captured: Vec<String> = if stored.origin == Origin::Proxy {
        stored_hosts
            .iter()
            .filter_map(|h| plain_host(h))
            .map(|(name, _)| name)
            .collect()
    } else {
        Vec::new()
    };
    let mut elsewhere: Vec<String> = Vec::new();
    for h in host_headers
        .iter()
        .map(|h| h.trim())
        .filter(|h| !h.is_empty())
    {
        let hd = guard::parse_target(&format!("{}://{}", dest.scheme, h))
            .map_err(|e| Refusal::invalid(format!("Host header: {}", untrusted::clean(&e, 200))))?;
        if !names_dest(h, &dest, &captured) && !elsewhere.iter().any(|e| e == h) {
            elsewhere.push(h.to_string());
        }
        let port = if h.contains(':') { hd.port } else { dest.port };
        if !mcp.guard.admit(
            &hd.host,
            port,
            Point::Repeater,
            Some("crossfyre mcp workbench_replay Host header"),
        ) {
            return Err(Refusal::new(
                Reason::OutOfScope,
                format!(
                    "Out of scope: the Host header names {}:{port}, which the scope file does \
                     not list. Nothing was sent.",
                    untrusted::clean(&hd.host, 200)
                ),
            )
            .with_refused(vec![RefusedDest {
                host: untrusted::clean(&hd.host, 200),
                port,
                at: "host_header",
            }]));
        }
    }
    let asked = match &overridden {
        Some(a) => a.describe(&untrusted::clean(&method, 32)),
        None => format!("{} request", untrusted::clean(&method, 32)),
    };
    let under = untrusted::clean(
        &elsewhere
            .iter()
            .map(|h| format!("\"{h}\""))
            .collect::<Vec<_>>()
            .join(", "),
        200,
    );
    // A yes is remembered for the captured host and the Host names it went out under,
    // so a yes for one pair never covers another.
    let pair = if elsewhere.is_empty() {
        dest.key()
    } else {
        format!("{} under Host {:?}", dest.key(), elsewhere)
    };
    let write = if intent == Intent::Write {
        let host_note = if elsewhere.is_empty() {
            String::new()
        } else {
            format!(
                " The Host header names {under}, so a server that routes by Host can hand that \
                 session to {under}."
            )
        };
        Some(WriteAsk {
            remember: Some(pair),
            message: format!(
                "workbench_replay will send a {asked} to {} from the Workbench project {}, with \
                 the cookies and headers that were captured, so it acts as the captured user.\
                 {host_note} Methods other than GET, HEAD and OPTIONS can change or destroy \
                 data. Allow them to {}{} for the rest of this session?",
                untrusted::clean(&dest.origin(), 200),
                o.name(),
                untrusted::clean(&dest.key(), 200),
                if elsewhere.is_empty() {
                    String::new()
                } else {
                    format!(" under Host {under}")
                }
            ),
            kind: AskKind::Write,
        })
    } else if !elsewhere.is_empty() {
        Some(WriteAsk {
            remember: Some(format!("read {pair}")),
            message: format!(
                "workbench_replay will send a {asked} to {} from the Workbench project {} with \
                 the Host header changed to {under}, carrying the cookies and headers captured \
                 for {}. A server that routes by Host can hand that session to {under}. Allow \
                 reads from {} to go out under Host {under} for the rest of this session?",
                untrusted::clean(&dest.origin(), 200),
                o.name(),
                untrusted::clean(&dest.host, 200),
                untrusted::clean(&dest.key(), 200)
            ),
            kind: AskKind::OtherHost,
        })
    } else {
        None
    };
    let clearance = mcp.confirm(pending, peer, write, note, ct).await?;

    // A compressed body is no use to a model, so ask for none unless the edits say
    // otherwise.
    let mut identity = false;
    let names_encoding = edits
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("accept-encoding"));
    if !names_encoding && edits.headers.len() < EDIT_ENTRIES_MAX {
        edits
            .headers
            .0
            .push(("accept-encoding".into(), Some("identity".into())));
        identity = true;
    }
    let pins: Vec<_> = clearance.cleared[0]
        .addrs
        .iter()
        .take(PINS_MAX)
        .copied()
        .collect();
    let call = Call::Replay(ReplayParams {
        project_uid: o.project.uid.clone(),
        id: h.id,
        edits,
        pins,
        label: bridge_label(&peer.label()),
        mcp: McpRef {
            session: mcp.session.clone(),
            seq: note.seq,
        },
        max_body_bytes: max,
    });
    let sent: ReplayResult = match ask(&o, &call, REPLAY_WAIT, ct).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return Err(replay_refusal(e, &o, &dest)),
        Err(r) if r.reason == Reason::Cancelled => {
            return Err(Refusal::new(
                Reason::Cancelled,
                "The call was cancelled and the Workbench was told to stop. A request already \
                 on its way may still have been sent and recorded; workbench_list_history with \
                 origins [\"agent\"] shows it if so.",
            ));
        }
        Err(r) => return Err(r),
    };

    let redact = mcp.settings.redact;
    let mut truncated = false;
    let headers = shown_headers(&sent.resp_headers, redact, &mut truncated);
    let mut applied: Vec<String> = sent
        .applied
        .iter()
        .take(60)
        .map(|s| untrusted::clean(s, 200))
        .collect();
    if identity
        && !applied
            .iter()
            .any(|s| s.to_ascii_lowercase().contains("accept-encoding"))
    {
        applied.push("accept-encoding set to identity, so the body comes back readable".into());
    }
    let request_line = untrusted::clean(&sent.request_line, 2048);
    let request_line = if redact {
        crate::redact::redact_request_line(&request_line)
    } else {
        request_line
    };
    let new_exchange = o.handle(sent.new_id);
    let mut value = json!({
        "workbench": o.shown(),
        "status": sent.status,
        "timing_ms": sent.duration_ms,
        "new_exchange": new_exchange,
        "applied_edits": applied,
        "target_data": {
            "untrusted": true,
            "request_line": request_line,
            "response": {
                "headers": headers,
                "body": sent.resp_body.as_ref().map(|b| shown_body(b, max as usize, redact)),
            },
            "truncated": truncated,
        },
    });
    let summary = format!(
        "{} {} answered {} in {} ms through the Workbench; recorded in project {} as {}.",
        untrusted::clean(&method, 32),
        untrusted::clean(&dest.origin(), 200),
        sent.status
            .map_or_else(|| "nothing".to_string(), |s| format!("HTTP {s}")),
        sent.duration_ms,
        o.name(),
        new_exchange.as_deref().unwrap_or("a new exchange")
    );
    fit(&summary, &mut value, &EXCHANGE_TEXTS[1..], "/target_data");
    note.result = Some(json!({"status": sent.status, "new_exchange": new_exchange}));
    Ok(Done { value, summary })
}

/// The client's name as the Workbench records and shows it: the bridge refuses a label
/// with a control character in it or one over `LABEL_MAX` bytes, and the agent can do
/// nothing about the name its client gave. A tab or newline becomes a space.
fn bridge_label(raw: &str) -> String {
    let one_line: String = untrusted::clean(raw, cfx_bridge::LABEL_MAX)
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let (capped, _) = untrusted::cap_bytes(one_line.trim(), cfx_bridge::LABEL_MAX);
    match capped.trim() {
        "" => "unknown".into(),
        t => t.to_string(),
    }
}

/// A Host value written plainly: a name of ASCII letters, digits, dots and hyphens, or
/// an IPv6 address in brackets, then at most a port in digits with no leading zero.
/// Returns the name lowercased (brackets kept) and the port. Anything else, such as a
/// percent sign, a non-ASCII letter, a slash or a `#`, is `None`: a URL parser and a
/// front end can read such a value as two different hosts.
fn plain_host(raw: &str) -> Option<(String, Option<u16>)> {
    let t = raw.trim().to_ascii_lowercase();
    let (name, port) = if t.starts_with('[') {
        let end = t.find(']')?;
        let inner = &t[1..end];
        if inner.is_empty()
            || !inner
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
        {
            return None;
        }
        (&t[..=end], &t[end + 1..])
    } else {
        let end = t.find(':').unwrap_or(t.len());
        let name = &t[..end];
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        {
            return None;
        }
        (name, &t[end..])
    };
    let port = match port {
        "" => None,
        p => {
            let digits = p.strip_prefix(':')?;
            let n: u16 = digits.parse().ok()?;
            if n.to_string() != digits {
                return None;
            }
            Some(n)
        }
    };
    Some((name.to_string(), port))
}

/// Whether a Host value, as it goes out, names the host the Workbench dials (or one the
/// browser sent this request under): the same plain name, with no port or with the
/// URL's port or the scheme's default.
fn names_dest(raw: &str, dest: &guard::Dest, captured: &[String]) -> bool {
    let Some((name, port)) = plain_host(raw) else {
        return false;
    };
    let default = if dest.scheme == "https" { 443 } else { 80 };
    if port.is_some_and(|p| p != dest.port && p != default) {
        return false;
    }
    let own = match dest.ip {
        Some(std::net::IpAddr::V6(_)) => format!("[{}]", dest.host),
        _ => dest.host.clone(),
    };
    name == own || captured.contains(&name)
}

/// The Host headers the sent request will carry. An edit that names Host sets the first
/// one, or adds one, and leaves any others as they were captured; `null` removes them all.
fn sent_hosts(stored: &[String], edited: Option<Option<String>>) -> Vec<String> {
    match edited {
        None => stored.to_vec(),
        Some(None) => Vec::new(),
        Some(Some(v)) => std::iter::once(v)
            .chain(stored.iter().skip(1).cloned())
            .collect(),
    }
}

/// A replay the Workbench refused or could not finish.
fn replay_refusal(e: crate::workbench::BridgeErr, o: &Open, dest: &guard::Dest) -> Refusal {
    use crate::workbench::BridgeErr;
    let host = untrusted::clean(&dest.host, 200);
    match e {
        BridgeErr::Remote(b) if b.code == ErrorCode::OutOfScope => Refusal::new(
            Reason::WorkbenchOutOfScope,
            format!(
                "Out of the project's scope: the Workbench project {} does not admit \
                 {host}:{} (or the Host header's host), so the Workbench sent nothing and \
                 recorded the refusal in the project. The scope file admits it; a send has to \
                 be admitted by both. Only the operator can change the project's scope.",
                o.name(),
                dest.port
            ),
        )
        .with_refused(vec![RefusedDest {
            host,
            port: dest.port,
            at: "workbench_scope",
        }]),
        BridgeErr::Remote(b) if b.code == ErrorCode::PinMismatch => Refusal::new(
            Reason::Unresolvable,
            format!(
                "The Workbench's own lookup of {host} gave none of the addresses this server \
                 cleared, so nothing was sent. Addresses that change between two lookups are \
                 common behind a CDN; calling again normally works."
            ),
        )
        .with_detail(json!({"workbench_error": "pin_mismatch"})),
        // The Workbench says so for a refused connection, and as much for a timeout or a
        // connection dropped after the request was written. Which it was is in its words,
        // not its code, and no exchange is recorded either way.
        BridgeErr::Remote(b) if b.code == ErrorCode::SendFailed => Refusal::new(
            Reason::RequestFailed,
            format!(
                "The Workbench's send failed: {}. It may have reached the target before it \
                 failed, and the project has no record of it, so a request that writes may \
                 already have taken effect.",
                untrusted::clean(&b.message, 300)
            ),
        )
        .with_detail(json!({"workbench_error": "send_failed"})),
        e @ (BridgeErr::Closed | BridgeErr::Timeout) => bridge_refusal(
            e,
            o,
            "The request may have been sent; workbench_list_history with origins [\"agent\"] \
             shows it if so.",
        ),
        e => bridge_refusal(e, o, "Nothing was sent."),
    }
}

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

/// What the request as it will be sent asks for by override, when that is not a read:
/// a GET carrying `X-HTTP-Method-Override: DELETE` or `_method=DELETE`. Only a replaced
/// body is read, since the captured one is not fetched for this.
///
/// The headers and query are taken as the Workbench will send them, each edit applied
/// the way it applies one, and then read however a target may spell or split them.
fn overriding_write(stored: &ExchangeResult, edits: &Edits) -> Option<Asked> {
    let mut asked: Vec<Asked> = Vec::new();
    let captured_headers = stored.req_headers.as_deref().unwrap_or(&[]);
    for (k, v) in sent_headers(captured_headers, &edits.headers) {
        if let Some(h) = overrides::header(&k) {
            asked.push(Asked::new(Via::Header(h), Some(&v)));
        }
    }
    let target = edits.path.as_deref().unwrap_or(&stored.url);
    let query = target.split_once('?').map_or("", |(_, q)| q);
    for (k, v) in overrides::pairs(&sent_query(query, &edits.query)) {
        if overrides::is_field(&k) {
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
    let is_host = |k: &str| k.trim().eq_ignore_ascii_case("host");
    let stored_hosts: Vec<String> = stored
        .req_headers
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .filter(|(k, _)| is_host(k))
        .map(|(_, v)| v.clone())
        .collect();
    let sent = sent_headers(stored.req_headers.as_deref().unwrap_or(&[]), &edits.headers);

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
    // An empty Host, or none at all, is not that name either: a front end sends such a
    // request to its default site. Neither has a name to admit. A stored request with
    // no Host asks too, since an earlier replay may have taken it out.
    //
    // A front end can route by X-Forwarded-Host or Forwarded instead, so a name those
    // give is held to the same rule.
    let captured: Vec<String> = if stored.origin == Origin::Proxy {
        stored_hosts
            .iter()
            .filter_map(|h| plain_host(h))
            .map(|(name, _)| name)
            .collect()
    } else {
        Vec::new()
    };
    // Each way the request names another host, as the question shows it, Host first.
    // A forwarding value is shown only as a plain host name, so the request cannot
    // write its own text into the question, and a name that is not plain is refused.
    // Every entry is bounded and none is cut, so nothing can push another out of view.
    // `keyed` holds the values as sent, for the remembered yes.
    let mut hosts: Vec<String> = Vec::new();
    let mut forwarded: Vec<String> = Vec::new();
    let mut keyed: Vec<String> = Vec::new();
    fn add(list: &mut Vec<String>, what: String) {
        if !list.contains(&what) {
            list.push(what);
        }
    }
    let host_headers: Vec<&str> = sent
        .iter()
        .filter(|(k, _)| is_host(k))
        .map(|(_, v)| v.as_str())
        .collect();
    if host_headers.is_empty() {
        add(&mut hosts, "no Host header".into());
        add(&mut keyed, "no Host header".into());
    }
    for raw in host_headers {
        let h = ows(raw);
        let shown = format!("Host {}", quoted(raw));
        if shown.len() > SHOWN_MAX {
            return Err(Refusal::invalid(
                "Host header: too long to show in a question. Nothing was sent.",
            ));
        }
        if h.is_empty() {
            add(&mut hosts, shown.clone());
            add(&mut keyed, shown);
            continue;
        }
        let hd = guard::parse_target(&format!("{}://{}", dest.scheme, h))
            .map_err(|e| Refusal::invalid(format!("Host header: {}", untrusted::clean(&e, 200))))?;
        if !names_dest(h, &dest, &captured) {
            add(&mut hosts, shown.clone());
            add(&mut keyed, shown);
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
    for (k, v) in &sent {
        let Some(f) = forwarding(k) else { continue };
        let mut named = false;
        for name in forwarded_names(f, v) {
            if names_dest(&name, &dest, &captured) {
                continue;
            }
            if name.len() > NAME_MAX || plain_host(&name).is_none() {
                return Err(Refusal::invalid(format!(
                    "{f} header: it names a host that is not written as a plain host name \
                     (letters, digits, dots and hyphens, then at most a port), so a question \
                     cannot show it. Give plain names, or remove the header with null. \
                     Nothing was sent."
                )));
            }
            named = true;
            add(&mut forwarded, format!("{f} {name}"));
        }
        if named {
            add(&mut keyed, format!("{f} {}", quoted(v)));
        }
    }
    let mut elsewhere = hosts;
    elsewhere.extend(forwarded);
    if elsewhere.len() > SHOWN_ENTRIES {
        return Err(Refusal::invalid(format!(
            "The Host and forwarding headers name {} other hosts, more than the {SHOWN_ENTRIES} \
             a question can show. Nothing was sent.",
            elsewhere.len()
        )));
    }
    let asked = match &overridden {
        Some(a) => a.describe(&untrusted::clean(&method, 32)),
        None => format!("{} request", untrusted::clean(&method, 32)),
    };
    // Every entry is printable ASCII and bounded, so this cap never cuts one.
    let under = untrusted::clean(&elsewhere.join(", "), SHOWN_ENTRIES * (SHOWN_MAX + 2));
    // A yes is remembered for the captured host and the Host values it went out under,
    // so a yes for one pair never covers another.
    let pair = if keyed.is_empty() {
        dest.key()
    } else {
        format!("{} with {:?}", dest.key(), keyed)
    };
    let write = if intent == Intent::Write {
        let host_note = if elsewhere.is_empty() {
            String::new()
        } else {
            format!(
                " It goes out with {under}, so a server that routes by Host or a forwarding \
                 header can hand that session to another site."
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
                    format!(" with {under}")
                }
            ),
            kind: AskKind::Write,
        })
    } else if !elsewhere.is_empty() {
        Some(WriteAsk {
            remember: Some(format!("read {pair}")),
            message: format!(
                "workbench_replay will send a {asked} to {} from the Workbench project {} with \
                 {under}, carrying the cookies and headers captured for {}. A server that \
                 routes by Host or a forwarding header can hand that session to another site. \
                 Allow reads from {} to go out with {under} for the rest of this session?",
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
    let t = ows(raw).to_ascii_lowercase();
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

/// The headers the sent request will carry, as the Workbench applies header edits: a
/// value sets the first header of that name, ignoring case, or adds one, and `null`
/// removes every header of that name.
fn sent_headers(stored: &[(String, String)], edits: &cfx_bridge::Pairs) -> Vec<(String, String)> {
    let mut out = stored.to_vec();
    for (name, value) in edits.iter() {
        let is = |k: &str| k.trim().eq_ignore_ascii_case(name);
        match value {
            Some(v) => match out.iter_mut().find(|(k, _)| is(k)) {
                Some(h) => h.1 = v.to_string(),
                None => out.push((name.to_string(), v.to_string())),
            },
            None => out.retain(|(k, _)| !is(k)),
        }
    }
    out
}

/// The raw query the sent request will carry, as the Workbench applies query edits: to
/// the `&`-separated parameters whose decoded name is the edit's name exactly. A value
/// replaces the first one's value, encoded, or is added at the end, and `null` removes
/// every one. Anything else, a pair joined by `;` included, stays as captured.
fn sent_query(captured: &str, edits: &cfx_bridge::Pairs) -> String {
    fn key(pair: &str) -> &str {
        pair.split_once('=').map_or(pair, |(k, _)| k)
    }
    let mut pairs: Vec<String> = captured.split('&').map(str::to_string).collect();
    for (name, value) in edits.iter() {
        let is = |p: &str| !p.is_empty() && overrides::decode(key(p)) == name;
        match value {
            Some(v) => match pairs.iter_mut().find(|p| is(p)) {
                Some(p) => *p = format!("{}={}", key(p), overrides::encode(v)),
                None => pairs.push(format!(
                    "{}={}",
                    overrides::encode(name),
                    overrides::encode(v)
                )),
            },
            None => pairs.retain(|p| !is(p)),
        }
    }
    pairs.join("&")
}

/// The spaces and tabs HTTP takes off either end of a header value. Any other white
/// space is part of the value, and the Workbench sends it as written.
fn ows(s: &str) -> &str {
    s.trim_matches([' ', '\t'])
}

/// A value as a question shows it: in quotes, with anything but printable ASCII spelt
/// out as an escape, so an invisible character is seen rather than dropped.
fn quoted(raw: &str) -> String {
    let mut out = String::from("\"");
    for c in raw.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            ' '..='~' => out.push(c),
            _ => out.push_str(&format!("\\u{{{:x}}}", c as u32)),
        }
    }
    out.push('"');
    out
}

/// Headers a front end can route by in place of Host, by their usual spelling.
const FORWARDING: [&str; 6] = [
    "X-Forwarded-Host",
    "X-Original-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-HTTP-Host-Override",
    "Forwarded",
];

/// The longest host name a forwarding header's entry shows: 253 characters of name,
/// brackets and a port. A longer one is refused.
const NAME_MAX: usize = 262;

/// The longest one entry of the other-host list may be as shown. A Host value longer
/// than that, escapes included, is refused.
const SHOWN_MAX: usize = 300;

/// The most entries the other-host list shows. A request naming more is refused, so a
/// yes never covers a name the question left out.
const SHOWN_ENTRIES: usize = 6;

/// The forwarding header a name is, ignoring case, with `_` read as `-`.
pub(super) fn forwarding(name: &str) -> Option<&'static str> {
    let name = name.trim().replace('_', "-");
    FORWARDING
        .into_iter()
        .find(|h| h.eq_ignore_ascii_case(&name))
}

/// The host names a forwarding header's value gives: each item of a list, or each
/// `host=` parameter of `Forwarded`, unquoted. An empty item names nothing.
fn forwarded_names(header: &str, value: &str) -> Vec<String> {
    if header != "Forwarded" {
        return value
            .split(',')
            .map(ows)
            .filter(|h| !h.is_empty())
            .map(str::to_string)
            .collect();
    }
    value
        .split([',', ';'])
        .filter_map(|p| p.split_once('='))
        .filter(|(k, _)| ows(k).eq_ignore_ascii_case("host"))
        .map(|(_, v)| {
            let v = ows(v);
            v.strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .unwrap_or(v)
                .to_string()
        })
        .collect()
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

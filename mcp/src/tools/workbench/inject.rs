//! `workbench_test_injection`: a captured request tested for injection by plessor,
//! signed in as the captured session.
//!
//! The request is read whole from the project, and its cookies and headers are handed
//! to plessor on loopback as the scan's `auth`. They are never written to a job file, a
//! result or the audit log. The destination has to be admitted by the scope file and by
//! the open project's scope, plessor's follow-ups are held to what both lists admit, and
//! the scan is cancelled if the project's scope stops admitting it or the project closes.

use super::{ask, bridge_refusal, parse_handle, route};
use crate::confirm::WriteAsk;
use crate::core::{
    CallNote, Done, Intent, Mcp, Reason, Refusal, RefusedDest, RunningJob, RunningMap,
    TrafficRequest, cancel_job,
};
use crate::jobs::{self, JobStore};
use crate::peer::ClientPeer;
use crate::tools::inject::{Plan, parse_classes, start_scan};
use crate::tools::{in_range, parse_args};
use crate::workbench::{Instance, REQUEST_WAIT};
use crate::{guard, redact, untrusted};
use cfx_bridge::{
    Call, CheckParams, CheckResult, Dest, Event, ScanSourceParams, ScanSourceResult, ScopeParams,
    ScopeResult,
};
use cfx_scope::Point;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::broadcast::{self, error::RecvError};
use tokio_util::sync::CancellationToken;

const METHODS: [&str; 5] = ["GET", "POST", "PUT", "PATCH", "DELETE"];
const WRITE_METHODS: [&str; 3] = ["PUT", "PATCH", "DELETE"];

/// What a check made for this tool says in the project's refusal log.
const DETAIL: &str = "agent injection test";

/// The most query parameters or body fields one test takes.
const SITES_MAX: usize = 50;

/// Captured headers that are not handed to plessor: the ones a client sets from the
/// request it sends, the ones that would change how the connection is used, and the
/// ones that ask for a cached answer, since a 304 tells the scan nothing.
const NOT_HANDED_ON: [&str; 12] = [
    "host",
    "content-length",
    "content-type",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "upgrade",
    "te",
    "trailer",
    "accept-encoding",
    "if-none-match",
    "if-modified-since",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    exchange: String,
    #[serde(default)]
    params: Option<Vec<String>>,
    #[serde(default)]
    classes: Option<Vec<String>>,
    #[serde(default)]
    test_writes: bool,
    #[serde(default)]
    wait_seconds: Option<u64>,
}

/// One body field as plessor reads it.
#[derive(serde::Serialize)]
struct Field {
    name: String,
    value: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    ty: Option<&'static str>,
}

/// The fields of a body plessor can test, and how it sends them.
fn body_fields(src: &ScanSourceResult) -> Result<(Vec<Field>, &'static str), Refusal> {
    let Some(body) = src.body.as_deref().filter(|b| !b.trim().is_empty()) else {
        return Ok((Vec::new(), "form"));
    };
    let ct = src
        .content_type
        .clone()
        .or_else(|| {
            src.req_headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                .map(|(_, v)| v.clone())
        })
        .unwrap_or_default();
    let ct = ct
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if ct == "application/x-www-form-urlencoded" {
        let decoded = transport::Url::parse(&format!("http://form.invalid/?{}", body.trim()))
            .map_err(|_| Refusal::invalid("the form body of this request could not be read"))?;
        let fields = decoded
            .query_pairs()
            .map(|(k, v)| Field {
                name: k.into_owned(),
                value: v.into_owned(),
                ty: None,
            })
            .collect();
        return Ok((fields, "form"));
    }
    if ct == "application/json" || ct.ends_with("+json") {
        let v: Value = serde_json::from_str(body)
            .map_err(|_| Refusal::invalid("the JSON body of this request does not parse"))?;
        let Value::Object(members) = v else {
            return Err(Refusal::invalid(
                "the JSON body of this request is not an object, so it has no members to test",
            ));
        };
        let fields = members
            .into_iter()
            .map(|(name, v)| {
                let (value, ty) = match v {
                    Value::String(s) => (s, Some("string")),
                    Value::Number(n) if n.is_i64() || n.is_u64() => {
                        (n.to_string(), Some("integer"))
                    }
                    Value::Number(n) => (n.to_string(), Some("number")),
                    Value::Bool(b) => (b.to_string(), Some("boolean")),
                    Value::Array(_) => (v.to_string(), Some("array")),
                    Value::Object(_) => (v.to_string(), Some("object")),
                    Value::Null => (String::new(), None),
                };
                Field { name, value, ty }
            })
            .collect();
        return Ok((fields, "json"));
    }
    // The captured type is the target's text, so it goes under target_data rather than
    // into the sentence a model reads as this server's.
    if ct.is_empty() {
        return Err(Refusal::invalid(
            "the body of this request has no stated type; plessor tests query parameters, form \
             fields and the members of a JSON object",
        ));
    }
    Err(Refusal::invalid(
        "the body of this request is of a type plessor does not test (its Content-Type is \
         under target_data); plessor tests query parameters, form fields and the members of a \
         JSON object",
    )
    .with_detail(json!({"target_data": {
        "untrusted": true,
        "content_type": untrusted::clean(&ct, 100),
    }})))
}

/// Names from the captured request, for a refusal's `target_data`.
fn names_shown(names: &[String]) -> Value {
    Value::Array(
        names
            .iter()
            .take(SITES_MAX)
            .map(|n| json!(untrusted::clean(n, 200)))
            .collect(),
    )
}

/// The captured cookies and headers, as plessor's `auth`. `None` when there are none.
fn session(src: &ScanSourceResult) -> Option<Value> {
    let mut headers = Map::new();
    let mut cookies: Vec<String> = Vec::new();
    for (k, v) in &src.req_headers {
        let name = k.trim().to_ascii_lowercase();
        if name == "cookie" {
            if !v.trim().is_empty() {
                cookies.push(v.trim().to_string());
            }
            continue;
        }
        if NOT_HANDED_ON.contains(&name.as_str())
            || name.starts_with("proxy-")
            || transport::HeaderName::from_bytes(name.as_bytes()).is_err()
            || transport::HeaderValue::from_str(v).is_err()
        {
            continue;
        }
        let joined = match headers.get(&name).and_then(Value::as_str) {
            Some(before) => format!("{before}, {v}"),
            None => v.clone(),
        };
        headers.insert(name, Value::String(joined));
    }
    if headers.is_empty() && cookies.is_empty() {
        return None;
    }
    Some(json!({"headers": headers, "cookies": cookies.join("; ")}))
}

/// One scope entry, read the way the scope crate reads it.
#[derive(Debug, PartialEq)]
enum Entry {
    Host(String),
    HostPort(String, u16),
    Zone(String),
    Range(IpAddr, u8),
}

fn entry(raw: &str) -> Option<Entry> {
    let e = raw.trim().to_ascii_lowercase();
    if let Some((a, bits)) = e.split_once('/') {
        return Some(Entry::Range(a.parse().ok()?, bits.parse().ok()?));
    }
    if let Some(base) = e.strip_prefix("*.") {
        return Some(Entry::Zone(base.to_string()));
    }
    if let Ok(ip) = e.parse::<IpAddr>() {
        return Some(Entry::Host(ip.to_string()));
    }
    if let Some(inner) = e.strip_prefix('[') {
        let (addr, rest) = inner.split_once(']')?;
        let ip: IpAddr = addr.parse().ok()?;
        return match rest {
            "" => Some(Entry::Host(ip.to_string())),
            p => Some(Entry::HostPort(
                ip.to_string(),
                p.strip_prefix(':')?.parse().ok()?,
            )),
        };
    }
    match e.rsplit_once(':') {
        Some((h, p)) => Some(Entry::HostPort(h.to_string(), p.parse().ok()?)),
        None => Some(Entry::Host(e)),
    }
}

/// Does `by` admit everything `e` admits.
fn covers(by: &cfx_scope::Scope, e: &Entry) -> bool {
    match e {
        Entry::Host(h) => by.admits(h, None),
        Entry::HostPort(h, p) => by.admits(h, Some(*p)),
        Entry::Zone(base) => by.admits_zone(base, true),
        Entry::Range(ip, bits) => by.admits_range(*ip, *bits),
    }
}

/// The entries both lists admit: each entry of one list that the other admits whole.
/// Never wider than either list. An entry that admits only part of what the other list
/// does is left out, which can only narrow the result.
pub(crate) fn both(a: &[String], b: &[String]) -> Vec<String> {
    let (sa, _) = cfx_scope::parse(a);
    let (sb, _) = cfx_scope::parse(b);
    let mut out: Vec<String> = Vec::new();
    let kept = a
        .iter()
        .filter(|e| entry(e).is_some_and(|x| covers(&sb, &x)))
        .chain(
            b.iter()
                .filter(|e| entry(e).is_some_and(|x| covers(&sa, &x))),
        );
    for e in kept {
        let e = e.trim().to_ascii_lowercase();
        if !out.contains(&e) {
            out.push(e);
        }
    }
    out
}

pub(crate) async fn run(
    mcp: &Mcp,
    args: &Value,
    peer: &dyn ClientPeer,
    ct: &CancellationToken,
    note: &mut CallNote,
) -> Result<Done, Refusal> {
    let a: Args = parse_args(args)?;
    let wait = in_range("wait_seconds", a.wait_seconds.unwrap_or(0), 0, 50)?;
    let classes = parse_classes(a.classes.clone())?;
    let named = a.params.clone().unwrap_or_default();
    if named.len() > SITES_MAX || named.iter().any(|p| p.len() > 200) {
        return Err(Refusal::invalid(
            "params holds at most 50 names of at most 200 characters",
        ));
    }
    let h = parse_handle(&a.exchange)?;
    let o = route(mcp, "workbench_test_injection", None, Some(h.project)).await?;
    note.workbench = Some(o.audit());
    // Before anything is asked, so no change to the project's scope can be missed
    // between the check below and the scan starting.
    let Some(events) = o.inst.subscribe() else {
        return Err(super::unavailable(mcp));
    };
    let src: ScanSourceResult = ask(
        &o,
        &Call::ScanSource(ScanSourceParams {
            project_uid: o.project.uid.clone(),
            id: h.id,
        }),
        REQUEST_WAIT,
        ct,
    )
    .await?
    .map_err(|e| bridge_refusal(e, &o, "Nothing was sent."))?;

    let method = src.method.trim().to_ascii_uppercase();
    if !METHODS.contains(&method.as_str()) {
        return Err(Refusal::invalid(
            "this request's method (under target_data) is not one plessor tests; it tests GET, \
             POST, PUT, PATCH and DELETE requests",
        )
        .with_detail(json!({"target_data": {
            "untrusted": true,
            "method": untrusted::clean(&method, 32),
        }})));
    }
    if WRITE_METHODS.contains(&method.as_str()) && !a.test_writes {
        return Err(Refusal::invalid(format!(
            "this is a {method} request, which can change or destroy data; it is tested only \
             with test_writes, which needs allow_writes in the scope file and a confirmation"
        )));
    }
    let dest = guard::parse_target(&src.url).map_err(|e| {
        Refusal::invalid(format!(
            "this exchange's URL cannot be tested: {}",
            untrusted::clean(&e, 200)
        ))
    })?;
    let mut query: Vec<String> = Vec::new();
    if let Ok(u) = transport::Url::parse(&dest.url) {
        for (k, _) in u.query_pairs() {
            if !query.contains(&k.to_string()) {
                query.push(k.into_owned());
            }
        }
    }
    let (mut fields, body_type) = body_fields(&src)?;
    if !named.is_empty() {
        let in_query: Vec<String> = query
            .iter()
            .filter(|q| named.contains(q))
            .cloned()
            .collect();
        let field_names: Vec<String> = fields.iter().map(|f| f.name.clone()).collect();
        fields.retain(|f| named.contains(&f.name));
        // The names are the target's text: they are listed under target_data, never in
        // the sentence.
        if in_query.is_empty() && fields.is_empty() {
            return Err(Refusal::invalid(
                "none of params is a query parameter, form field or JSON member of this \
                 request; the names it has are under target_data",
            )
            .with_detail(json!({"target_data": {
                "untrusted": true,
                "query_parameters": names_shown(&query),
                "body_fields": names_shown(&field_names),
            }})));
        }
        // plessor reads an empty list as every query parameter of the URL.
        if in_query.is_empty() && !query.is_empty() {
            return Err(Refusal::invalid(
                "plessor tests every query parameter of the URL unless at least one is named; \
                 name one of the query parameters under target_data as well, or leave params \
                 out",
            )
            .with_detail(json!({"target_data": {
                "untrusted": true,
                "query_parameters": names_shown(&query),
            }})));
        }
        query = in_query;
    }
    if query.is_empty() && fields.is_empty() {
        return Err(Refusal::invalid(
            "this request has no query parameters, form fields or JSON members to test",
        ));
    }
    if query.len() > SITES_MAX || fields.len() > SITES_MAX {
        return Err(Refusal::invalid(format!(
            "this request has more than {SITES_MAX} query parameters or body fields; name up to \
             {SITES_MAX} with params"
        )));
    }

    let pending = mcp
        .precheck(TrafficRequest {
            tool: "workbench_test_injection",
            dests: vec![dest.clone()],
            intent: if a.test_writes {
                Intent::Write
            } else {
                Intent::Read
            },
            point: Point::Request,
            pace: false,
            scan_start: true,
        })
        .await?;
    // The project's scope, which records a refusal as a send would.
    let target = Dest {
        host: dest.host.clone(),
        port: dest.port,
    };
    let checked: CheckResult = ask(
        &o,
        &Call::Check(CheckParams {
            project_uid: o.project.uid.clone(),
            dests: vec![target.clone()],
            record: true,
            detail: Some(DETAIL.into()),
        }),
        REQUEST_WAIT,
        ct,
    )
    .await?
    .map_err(|e| bridge_refusal(e, &o, "Nothing was sent."))?;
    let admitted = checked
        .results
        .iter()
        .any(|r| r.admitted && r.host == target.host && r.port == target.port);
    if !admitted {
        return Err(Refusal::new(
            Reason::WorkbenchOutOfScope,
            format!(
                "Out of the project's scope: the Workbench project {} does not admit {}:{}, so \
                 nothing was sent and the refusal was recorded in the project. The scope file \
                 admits it; a test has to be admitted by both.",
                o.name(),
                untrusted::clean(&dest.host, 200),
                dest.port
            ),
        )
        .with_refused(vec![RefusedDest {
            host: untrusted::clean(&dest.host, 200),
            port: dest.port,
            at: "workbench_scope",
        }]));
    }
    // plessor's follow-ups go only where both lists reach. With the scope file alone it
    // could carry the captured session to a destination the project never lists.
    let project_scope: ScopeResult = ask(
        &o,
        &Call::Scope(ScopeParams {
            project_uid: o.project.uid.clone(),
        }),
        REQUEST_WAIT,
        ct,
    )
    .await?
    .map_err(|e| bridge_refusal(e, &o, "Nothing was sent."))?;
    let scope = if project_scope.restricted {
        let mut s = both(&mcp.scope.entries, &project_scope.entries);
        if s.is_empty() {
            s.push(dest.key());
        }
        s
    } else {
        mcp.scope.entries.clone()
    };

    let origin = dest.origin();
    let handle = o.handle(h.id);
    let op = json!({
        "method": method,
        "url": dest.url,
        "params": query,
        "body": fields,
        "body_type": body_type,
    });
    let write = a.test_writes.then(|| WriteAsk {
        remember: None,
        message: format!(
            "workbench_test_injection with test_writes will send DELETE, PUT and PATCH requests \
             to {} as the session captured in the Workbench project {}. These can change or \
             destroy data.",
            untrusted::clean(&origin, 200),
            o.name()
        ),
    });
    let on_start = keep_in_scope(
        Arc::clone(&o.inst),
        o.project.uid.clone(),
        target,
        events,
        Arc::clone(&mcp.jobs),
        Arc::clone(&mcp.running),
    );
    let plan = Plan {
        tool: "workbench_test_injection",
        origin,
        endpoints: vec![op],
        // The job file outlives the call; a token in the query does not go in it.
        shown_endpoints: vec![redact::redact_url(&dest.url)],
        classes,
        test_writes: a.test_writes,
        auth: session(&src),
        source: Some(json!({"workbench": {
            "pid": o.inst.pid,
            "project_uid": o.project.uid,
            "exchange": handle,
        }})),
        scope,
        wait,
        write,
        on_start: Some(Box::new(on_start)),
    };
    let mut done = start_scan(mcp, pending, plan, peer, ct, note).await?;
    done.value["workbench"] = o.shown();
    Ok(done)
}

/// Watch the project while the scan runs: when its scope changes or the project does,
/// check the destination again, and cancel the scan if it is no longer admitted.
fn keep_in_scope(
    inst: Arc<Instance>,
    uid: String,
    dest: Dest,
    mut events: broadcast::Receiver<Event>,
    store: Arc<JobStore>,
    running: RunningMap,
) -> impl FnOnce(Arc<RunningJob>) + Send + 'static {
    move |job: Arc<RunningJob>| {
        tokio::spawn(async move {
            let mut snap = job.snap.clone();
            loop {
                if jobs::is_terminal(&snap.borrow_and_update().status) {
                    return;
                }
                let why = tokio::select! {
                    ev = events.recv() => match ev {
                        Ok(Event::Scope { .. } | Event::Project { .. }) | Err(RecvError::Lagged(_)) => {
                            still_admitted(&inst, &uid, &dest).await.err()
                        }
                        Ok(Event::AgentAccess { enabled: false }) => Some(
                            "Agent access was turned off in the Workbench, so the project's \
                             scope could no longer be checked"
                                .to_string(),
                        ),
                        Ok(_) => None,
                        Err(RecvError::Closed) => Some(
                            "the Workbench closed its connection, so the project's scope could \
                             no longer be checked"
                                .to_string(),
                        ),
                    },
                    r = snap.changed() => {
                        if r.is_err() {
                            return;
                        }
                        None
                    }
                };
                let Some(why) = why else { continue };
                if jobs::is_terminal(&snap.borrow().status) {
                    return;
                }
                if let Ok(mut m) = job.meta.lock() {
                    m.note(format!("cancelled: {why}"));
                }
                cancel_job(&store, &running, &job).await;
                return;
            }
        });
    }
}

async fn still_admitted(inst: &Arc<Instance>, uid: &str, dest: &Dest) -> Result<(), String> {
    let at = format!("{}:{}", untrusted::clean(&dest.host, 200), dest.port);
    match inst.project() {
        Some(p) if p.uid == uid => {}
        Some(p) => {
            return Err(format!(
                "the Workbench opened another project ({})",
                untrusted::clean(&p.name, 200)
            ));
        }
        None => return Err("the project was closed in the Workbench".into()),
    }
    let call = Call::Check(CheckParams {
        project_uid: uid.to_string(),
        dests: vec![dest.clone()],
        record: true,
        detail: Some(DETAIL.into()),
    });
    match inst.request::<CheckResult>(&call, REQUEST_WAIT).await {
        Ok(r)
            if r.results
                .iter()
                .any(|x| x.admitted && x.host == dest.host && x.port == dest.port) =>
        {
            Ok(())
        }
        Ok(_) => Err(format!("the project's scope no longer admits {at}")),
        Err(e) => Err(format!(
            "the Workbench could not say whether the project's scope still admits {at} ({})",
            e.describe()
        )),
    }
}

#[cfg(test)]
mod unit {
    use super::*;

    fn v(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn both_lists_is_never_wider_than_either() {
        // A name the project lists under a zone the file lists.
        assert_eq!(
            both(
                &v(&["*.example.com"]),
                &v(&["api.example.com", "other.test"])
            ),
            v(&["api.example.com"])
        );
        // One port of a host the other list takes on every port.
        assert_eq!(
            both(&v(&["app.example.com:8443"]), &v(&["app.example.com"])),
            v(&["app.example.com:8443"])
        );
        // A range inside a range, and an address inside one.
        assert_eq!(
            both(
                &v(&["10.0.0.0/8"]),
                &v(&["10.1.0.0/16", "10.2.3.4", "192.168.0.0/16"])
            ),
            v(&["10.1.0.0/16", "10.2.3.4"])
        );
        // A zone inside a zone.
        assert_eq!(
            both(&v(&["*.a.example.com"]), &v(&["*.example.com"])),
            v(&["*.a.example.com"])
        );
        assert_eq!(
            both(&v(&["[fd00::1]:8080"]), &v(&["fd00::/8"])),
            v(&["[fd00::1]:8080"])
        );
        // Nothing in common is nothing, not everything.
        assert!(both(&v(&["a.test"]), &v(&["b.test"])).is_empty());
        // The same entry on both sides is kept once.
        assert_eq!(both(&v(&["a.test"]), &v(&["A.test"])), v(&["a.test"]));
    }

    #[test]
    fn a_host_on_every_port_is_not_covered_by_one_port() {
        assert!(
            both(&v(&["app.example.com"]), &v(&["app.example.com:443"]))
                == v(&["app.example.com:443"])
        );
        assert!(
            !both(&v(&["app.example.com"]), &v(&["app.example.com:443"]))
                .contains(&"app.example.com".to_string())
        );
    }
}

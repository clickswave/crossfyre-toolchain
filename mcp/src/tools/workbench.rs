//! The `workbench_*` tools: a running Crossfyre Workbench's project, read and sent
//! through over its local socket.
//!
//! Each call goes to one Workbench, chosen by the handle or cursor it carries, or by the
//! project it names, and its result names the project it read. Whatever came from
//! captured traffic (URLs, paths, headers, bodies, the Repeater draft and refusal
//! details) is returned under `target_data`: stripped, capped, and masked by name and
//! format unless the server runs with `--no-redact`.

use super::{parse_args, result_size};
use crate::WorkbenchMode;
use crate::core::{CallNote, Done, Mcp, Reason, Refusal};
use crate::jobs::rfc3339;
use crate::peer::ClientPeer;
use crate::untrusted::{self, RESULT_CAP};
use crate::workbench::{BridgeErr, Instance, REQUEST_WAIT};
use crate::{guard, redact};
use cfx_bridge::{
    Body, Call, CheckParams, CheckResult, Cursor, Dest, Encoding, ErrorCode, ExchangeHandle,
    ExchangeParams, ExchangeResult, HistoryFilter, HistoryParams, HistoryResult, Origin, Part,
    ProjectInfo, ProjectTag, ScopeParams, ScopeResult, SelectionResult, SiteMapParams,
    SiteMapResult,
};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// One header value, and all of one side's headers, as returned.
const HEADER_VALUE_MAX: usize = 1024;
const HEADERS_TOTAL_MAX: usize = 8 * 1024;
/// A URL or path from a list row.
const URL_MAX: usize = 2048;

pub(crate) async fn run(
    mcp: &Mcp,
    tool: &str,
    args: &Value,
    _peer: &dyn ClientPeer,
    ct: &CancellationToken,
    note: &mut CallNote,
) -> Result<Done, Refusal> {
    if mcp.settings.workbench == WorkbenchMode::Off {
        return Err(unavailable(mcp));
    }
    match tool {
        "workbench_list_history" => list_history(mcp, args, ct, note).await,
        "workbench_get_exchange" => get_exchange(mcp, args, ct, note).await,
        "workbench_get_selection" => get_selection(mcp, args, ct, note).await,
        "workbench_get_site_map" => get_site_map(mcp, args, ct, note).await,
        "workbench_get_scope" => get_scope(mcp, args, ct, note).await,
        _ => Err(unavailable(mcp)),
    }
}

/// No Workbench to answer: what to do about it, in the person's terms.
pub(crate) fn unavailable(mcp: &Mcp) -> Refusal {
    let message = if mcp.settings.workbench == WorkbenchMode::Off {
        "This server was started with --workbench off, so it reaches no Workbench. Nothing \
         was read or sent."
    } else if !cfg!(unix) {
        "The Workbench bridge is not available on this platform. Nothing was read or sent."
    } else {
        "No Crossfyre Workbench with Agent access on is answering, so nothing was read or \
         sent. Open the Workbench (0.1.2 or later), turn Agent access on with the Agents chip \
         in its status bar, and call again. status shows what this server found."
    };
    Refusal::new(Reason::WorkbenchUnavailable, message)
}

/// The `workbench` object in `status`, and its hints.
pub(crate) async fn status(mcp: &Mcp, hints: &mut Vec<String>) -> Value {
    let mut v = json!({
        "mode": mcp.settings.workbench.as_str(),
        "supported": cfg!(unix),
        "dir": null,
        "instances": [],
        "ignored": [],
    });
    if mcp.settings.workbench == WorkbenchMode::Off {
        return v;
    }
    if !cfg!(unix) {
        hints.push("the Workbench bridge is not available on this platform".into());
        return v;
    }
    let found = mcp.workbench.status(hints).await;
    if let (Some(o), Some(f)) = (v.as_object_mut(), found.as_object()) {
        for (k, x) in f {
            o.insert(k.clone(), x.clone());
        }
    }
    let none = v["instances"].as_array().is_none_or(|a| a.is_empty());
    if none && mcp.settings.workbench == WorkbenchMode::Always {
        hints.push(
            "no Crossfyre Workbench with Agent access on was found, so the workbench_* tools \
             refuse; open one (0.1.2 or later) and turn Agent access on"
                .into(),
        );
    }
    v
}

// ---------------------------------------------------------------------------
// Which Workbench a call goes to

/// A Workbench and the project it has open, as this server last heard.
pub(crate) struct Open {
    pub inst: Arc<Instance>,
    pub project: ProjectInfo,
}

impl Open {
    pub(crate) fn tag(&self) -> ProjectTag {
        // Only built from projects whose uid was checked.
        ProjectTag::of(&self.project.uid).expect("a checked project uid")
    }

    pub(crate) fn handle(&self, id: i64) -> Option<String> {
        ExchangeHandle::new(&self.project.uid, id).map(|h| h.to_string())
    }

    pub(crate) fn name(&self) -> String {
        untrusted::clean(&self.project.name, 200)
    }

    /// The `workbench` object a result carries.
    pub(crate) fn shown(&self) -> Value {
        json!({
            "pid": self.inst.pid,
            "project": self.name(),
            "project_uid": self.project.uid,
        })
    }

    /// What the audit line records about where the call went.
    pub(crate) fn audit(&self) -> Value {
        json!({"pid": self.inst.pid, "project_uid": self.project.uid})
    }
}

fn listing(open: &[Open]) -> String {
    open.iter()
        .map(|o| format!("{} (pid {})", o.name(), o.inst.pid))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The Workbench a call goes to: the one whose open project a handle or cursor names,
/// the one with the project named, or the only one with a project open.
pub(crate) async fn route(
    mcp: &Mcp,
    tool: &str,
    project: Option<&str>,
    tag: Option<ProjectTag>,
) -> Result<Open, Refusal> {
    let mut all = mcp.workbench.instances();
    if all.is_empty() {
        // One may have started since the last look.
        mcp.workbench.refresh().await;
        all = mcp.workbench.instances();
    }
    if all.is_empty() {
        return Err(unavailable(mcp));
    }
    let needs = crate::workbench::needs(tool);
    let able: Vec<Arc<Instance>> = all
        .into_iter()
        .filter(|i| needs.iter().all(|m| i.welcome.supports(*m)))
        .collect();
    if able.is_empty() {
        return Err(Refusal::new(
            Reason::WorkbenchUnavailable,
            format!(
                "No Workbench connected here can answer {tool}; update the Workbench. Nothing \
                 was read or sent."
            ),
        ));
    }
    let open: Vec<Open> = able
        .iter()
        .filter_map(|i| {
            i.project()
                .filter(|p| cfx_bridge::is_project_uid(&p.uid))
                .map(|project| Open {
                    inst: Arc::clone(i),
                    project,
                })
        })
        .collect();
    if open.is_empty() {
        let pids: Vec<String> = able.iter().map(|i| i.pid.to_string()).collect();
        return Err(Refusal::new(
            Reason::WorkbenchError,
            format!(
                "No project is open in the Workbench (pid {}). Open a project in the \
                 Workbench and call again. Nothing was read or sent.",
                pids.join(", pid ")
            ),
        )
        .with_detail(json!({"workbench_error": "no_project"})));
    }
    let mut picked: Vec<Open> = match tag {
        Some(tag) => {
            let (hit, rest): (Vec<Open>, Vec<Open>) =
                open.into_iter().partition(|o| tag.matches(&o.project.uid));
            if hit.is_empty() {
                return Err(Refusal::new(
                    Reason::ProjectChanged,
                    format!(
                        "That handle or cursor is from a project that is not open in any \
                         Workbench now (open: {}). An exchange number means something only in \
                         its own project, so nothing was read or sent. List the history again \
                         for handles in the project that is open.",
                        listing(&rest)
                    ),
                )
                .with_detail(json!({
                    "open": rest.iter().map(Open::shown).collect::<Vec<_>>(),
                })));
            }
            if let Some(name) = project
                && hit.iter().all(|o| o.project.name != name)
            {
                return Err(Refusal::invalid(format!(
                    "the cursor is from project {}, not {}",
                    listing(&hit),
                    untrusted::clean(name, 200)
                )));
            }
            hit
        }
        None => match project {
            Some(name) => {
                let (hit, rest): (Vec<Open>, Vec<Open>) =
                    open.into_iter().partition(|o| o.project.name == name);
                if hit.is_empty() {
                    return Err(Refusal::invalid(format!(
                        "no Workbench has a project named {} open; open: {}",
                        untrusted::clean(name, 200),
                        listing(&rest)
                    )));
                }
                hit
            }
            None => open,
        },
    };
    match picked.len() {
        1 => Ok(picked.remove(0)),
        _ if project.is_some() || tag.is_some() => {
            let same = picked
                .iter()
                .all(|o| o.project.uid == picked[0].project.uid);
            Err(Refusal::new(
                Reason::WorkbenchError,
                if same {
                    format!(
                        "The same project is open in more than one Workbench: {}. Two \
                         processes writing one project file is worth fixing rather than \
                         choosing between, so nothing was read or sent. Close it in all but \
                         one.",
                        listing(&picked)
                    )
                } else {
                    format!(
                        "More than one open project has that name: {}. Rename or close one; \
                         nothing was read or sent.",
                        listing(&picked)
                    )
                },
            )
            .with_detail(json!({
                "workbench_error": "ambiguous",
                "open": picked.iter().map(Open::shown).collect::<Vec<_>>(),
            })))
        }
        _ => Err(Refusal::invalid(format!(
            "projects are open in more than one Workbench: {}. Name one with project.",
            listing(&picked)
        ))
        .with_detail(json!({
            "open": picked.iter().map(Open::shown).collect::<Vec<_>>(),
        }))),
    }
}

// ---------------------------------------------------------------------------
// Asking

/// Send one request, giving up when the call is cancelled. Dropping the request sends
/// the Workbench a `cancel` for it.
pub(crate) async fn ask<T: DeserializeOwned>(
    o: &Open,
    call: &Call,
    wait: Duration,
    ct: &CancellationToken,
) -> Result<Result<T, BridgeErr>, Refusal> {
    if let Err(why) = call.validate() {
        return Err(Refusal::invalid(untrusted::clean(&why, 300)));
    }
    tokio::select! {
        r = o.inst.request::<T>(call, wait) => Ok(r),
        _ = ct.cancelled() => Err(Refusal::new(
            Reason::Cancelled,
            "The call was cancelled before the Workbench answered.",
        )),
    }
}

/// What a Workbench error means here. `after` ends the sentence about what was or was
/// not done: "Nothing was read." for a read.
pub(crate) fn bridge_refusal(e: BridgeErr, o: &Open, after: &str) -> Refusal {
    let pid = o.inst.pid;
    match e {
        BridgeErr::Closed => Refusal::new(
            Reason::WorkbenchUnavailable,
            format!("The Workbench (pid {pid}) closed the connection before answering. {after}"),
        ),
        BridgeErr::Timeout => Refusal::new(
            Reason::WorkbenchError,
            format!("The Workbench (pid {pid}) did not answer in time. {after}"),
        )
        .with_detail(json!({"workbench_error": "timeout"})),
        BridgeErr::Bad(why) => Refusal::new(
            Reason::WorkbenchError,
            format!(
                "The Workbench's answer could not be read ({}). {after}",
                untrusted::clean(&why, 200)
            ),
        )
        .with_detail(json!({"workbench_error": "bad_answer"})),
        BridgeErr::Remote(b) => {
            let said = untrusted::clean(&b.message, 300);
            let code = untrusted::clean(b.code.as_str(), 40);
            let detail = json!({"workbench_error": code});
            match b.code {
                ErrorCode::ProjectChanged => {
                    let now = b
                        .current
                        .map(|c| untrusted::clean(&c.name, 200))
                        .unwrap_or_else(|| "another project".into());
                    Refusal::new(
                        Reason::ProjectChanged,
                        format!(
                            "The Workbench (pid {pid}) has {now} open now, not {}. {after} List \
                             the history again for handles in the project that is open.",
                            o.name()
                        ),
                    )
                }
                ErrorCode::NoProject => Refusal::new(
                    Reason::WorkbenchError,
                    format!(
                        "No project is open in the Workbench (pid {pid}) any more. {after} Open \
                         a project in the Workbench and call again."
                    ),
                )
                .with_detail(detail),
                ErrorCode::NotFound => Refusal::new(
                    Reason::NotFound,
                    format!("Project {} has no such exchange: {said}. {after}", o.name()),
                ),
                ErrorCode::InvalidParams => Refusal::invalid(format!(
                    "The Workbench refused the arguments: {said}. {after}"
                )),
                ErrorCode::Busy => Refusal::new(
                    Reason::RateLimited,
                    format!("The Workbench (pid {pid}) is busy with other requests. {after}"),
                )
                .with_detail(json!({"retry_after_seconds": 1, "workbench_error": "busy"})),
                ErrorCode::AccessOff => Refusal::new(
                    Reason::WorkbenchUnavailable,
                    format!(
                        "Agent access was turned off in the Workbench (pid {pid}). {after} Turn \
                         it on with the Agents chip in the status bar to use these tools again."
                    ),
                ),
                ErrorCode::SendFailed => Refusal::new(
                    Reason::RequestFailed,
                    format!("The Workbench could not send the request: {said}. {after}"),
                ),
                _ => Refusal::new(
                    Reason::WorkbenchError,
                    format!("The Workbench (pid {pid}) answered {code}: {said}. {after}"),
                )
                .with_detail(detail),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Shaping what came from traffic

pub(crate) fn shown_url(u: &str, redact: bool) -> String {
    let u = untrusted::clean(u, URL_MAX);
    if redact { redact::redact_url(&u) } else { u }
}

/// Headers as `[[name, value], ...]`: each value stripped and capped, masked by name, and
/// the whole side capped. Sets `truncated` when anything was cut.
pub(crate) fn shown_headers(h: &[(String, String)], redact: bool, truncated: &mut bool) -> Value {
    let mut out = Vec::new();
    let mut total = 0usize;
    for (k, v) in h {
        let k = untrusted::clean(k, 200);
        let (v, cut) = untrusted::sanitize(v, HEADER_VALUE_MAX);
        *truncated |= cut;
        let v = if redact {
            redact::redact_header(&k, &v)
        } else {
            v
        };
        total += k.len() + v.len();
        if total > HEADERS_TOTAL_MAX {
            *truncated = true;
            break;
        }
        out.push(json!([k, v]));
    }
    Value::Array(out)
}

/// A body: its text stripped, capped and masked, or for a binary one its length and first
/// bytes.
pub(crate) fn shown_body(b: &Body, cap: usize, redact: bool) -> Value {
    match b.encoding {
        Encoding::Text => {
            let (text, cut) = untrusted::sanitize(b.text.as_deref().unwrap_or(""), cap);
            let text = if redact {
                redact::redact_text(&text)
            } else {
                text
            };
            json!({"encoding": "text", "text": text, "len": b.len, "truncated": b.truncated || cut})
        }
        Encoding::Binary => json!({
            "encoding": "binary",
            "magic_hex": b.magic_hex.as_deref().map(|m| untrusted::clean(m, 32)),
            "len": b.len,
            "truncated": b.truncated,
        }),
    }
}

/// Halve the longest string at one of `texts` (JSON pointers) until the result fits,
/// marking each pointer's `truncated` sibling and `flag` as it goes.
pub(crate) fn fit(summary: &str, value: &mut Value, texts: &[&str], flag: &str) {
    while result_size(summary, value) > RESULT_CAP {
        let longest = texts
            .iter()
            .filter_map(|p| {
                value
                    .pointer(p)
                    .and_then(Value::as_str)
                    .map(|s| (*p, s.len()))
            })
            .filter(|(_, n)| *n > 0)
            .max_by_key(|(_, n)| *n);
        let Some((p, n)) = longest else { return };
        if let Some(Value::String(s)) = value.pointer_mut(p) {
            *s = untrusted::cap_bytes(s, n / 2).0;
        }
        if let Some((parent, _)) = p.rsplit_once('/')
            && let Some(Value::Object(o)) = value.pointer_mut(parent)
        {
            o.insert("truncated".into(), json!(true));
        }
        if let Some(Value::Object(o)) = value.pointer_mut(flag) {
            o.insert("truncated".into(), json!(true));
        }
    }
}

fn origin_str(o: &Origin) -> String {
    untrusted::clean(o.as_str(), 40)
}

/// One stored exchange, in the shape `workbench_get_exchange` returns.
fn exchange_view(o: &Open, x: &ExchangeResult, cap: usize, redact: bool) -> Value {
    let mut truncated = false;
    let mut td = json!({
        "untrusted": true,
        "url": shown_url(&x.url, redact),
    });
    if x.req_headers.is_some() || x.req_body.is_some() {
        let headers = shown_headers(
            x.req_headers.as_deref().unwrap_or(&[]),
            redact,
            &mut truncated,
        );
        td["request"] = json!({
            "headers": headers,
            "body": x.req_body.as_ref().map(|b| shown_body(b, cap, redact)),
        });
    }
    if x.resp_headers.is_some() || x.resp_body.is_some() {
        let headers = shown_headers(
            x.resp_headers.as_deref().unwrap_or(&[]),
            redact,
            &mut truncated,
        );
        td["response"] = json!({
            "headers": headers,
            "body": x.resp_body.as_ref().map(|b| shown_body(b, cap, redact)),
        });
    }
    td["truncated"] = json!(truncated);
    json!({
        "workbench": o.shown(),
        "exchange": o.handle(x.id),
        "method": untrusted::clean(&x.method, 32),
        "host": untrusted::clean(&x.host, 200),
        "status": x.status,
        "origin": origin_str(&x.origin),
        "actor": x.actor.as_deref().map(|a| untrusted::clean(a, 200)),
        "at": rfc3339(x.at_ms),
        "duration_ms": x.duration_ms,
        "pinned": x.pinned,
        "target_data": td,
    })
}

const EXCHANGE_TEXTS: [&str; 2] = [
    "/target_data/request/body/text",
    "/target_data/response/body/text",
];

// ---------------------------------------------------------------------------
// The read tools

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryArgs {
    #[serde(default)]
    project: Option<String>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    status_min: Option<u64>,
    #[serde(default)]
    status_max: Option<u64>,
    #[serde(default)]
    origins: Option<Vec<String>>,
    #[serde(default)]
    url_contains: Option<String>,
    #[serde(default)]
    search: Option<String>,
    #[serde(default)]
    since: Option<String>,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    limit: Option<u64>,
}

fn max_len(name: &str, v: &Option<String>, max: usize) -> Result<(), Refusal> {
    if v.as_ref().is_some_and(|s| s.len() > max) {
        return Err(Refusal::invalid(format!(
            "{name} is longer than {max} characters"
        )));
    }
    Ok(())
}

fn status_code(name: &str, v: Option<u64>) -> Result<Option<u16>, Refusal> {
    v.map(|s| super::in_range(name, s, 100, 599).map(|s| s as u16))
        .transpose()
}

fn parse_cursor(raw: &Option<String>, history: bool) -> Result<Option<Cursor>, Refusal> {
    let Some(raw) = raw else { return Ok(None) };
    let c: Cursor = raw.parse().map_err(|_| {
        Refusal::invalid("cursor is not one this server gave out; pass next_cursor as it came")
    })?;
    match (&c, history) {
        (Cursor::History { .. }, true) | (Cursor::SiteMap { .. }, false) => Ok(Some(c)),
        _ => Err(Refusal::invalid(
            "that cursor is for the other list; pass next_cursor from the same tool",
        )),
    }
}

async fn list_history(
    mcp: &Mcp,
    args: &Value,
    ct: &CancellationToken,
    note: &mut CallNote,
) -> Result<Done, Refusal> {
    let a: HistoryArgs = parse_args(args)?;
    max_len("project", &a.project, 200)?;
    max_len("host", &a.host, 253)?;
    max_len("method", &a.method, 16)?;
    max_len("url_contains", &a.url_contains, 2048)?;
    max_len("search", &a.search, 200)?;
    max_len("since", &a.since, 40)?;
    max_len("cursor", &a.cursor, 128)?;
    let limit = super::in_range("limit", a.limit.unwrap_or(50), 1, 100)? as u32;
    let status_min = status_code("status_min", a.status_min)?;
    let status_max = status_code("status_max", a.status_max)?;
    let mut origins = Vec::new();
    for o in a.origins.unwrap_or_default() {
        let parsed = Origin::parse(&o);
        if matches!(parsed, Origin::Other(_)) {
            return Err(Refusal::invalid(
                "origins holds proxy, repeater, replay or agent",
            ));
        }
        if !origins.contains(&parsed) {
            origins.push(parsed);
        }
    }
    let since_ms = match &a.since {
        Some(s) => Some(
            chrono::DateTime::parse_from_rfc3339(s.trim())
                .map_err(|_| Refusal::invalid("since is not an RFC 3339 time"))?
                .timestamp_millis(),
        ),
        None => None,
    };
    let cursor = parse_cursor(&a.cursor, true)?;
    let o = route(
        mcp,
        "workbench_list_history",
        a.project.as_deref(),
        cursor.as_ref().map(Cursor::project),
    )
    .await?;
    note.workbench = Some(o.audit());
    let filter = HistoryFilter {
        host: a.host.map(|h| h.trim().to_ascii_lowercase()),
        method: a.method.map(|m| m.trim().to_ascii_uppercase()),
        status_min,
        status_max,
        origins,
        url_contains: a.url_contains,
        search: a.search,
        since_ms,
        until_ms: None,
    };
    let call = Call::History(HistoryParams {
        project_uid: o.project.uid.clone(),
        filter,
        cursor: match cursor {
            Some(Cursor::History { at, .. }) => Some(at),
            _ => None,
        },
        limit,
    });
    let r: HistoryResult = ask(&o, &call, REQUEST_WAIT, ct)
        .await?
        .map_err(|e| bridge_refusal(e, &o, "Nothing was read."))?;

    let redact = mcp.settings.redact;
    let mut rows: Vec<(Value, cfx_bridge::HistoryCursor)> = Vec::new();
    for row in &r.rows {
        let Some(handle) = o.handle(row.id) else {
            continue;
        };
        rows.push((
            json!({
                "exchange": handle,
                "at": rfc3339(row.at_ms),
                "method": untrusted::clean(&row.method, 32),
                "host": untrusted::clean(&row.host, 200),
                "status": row.status,
                "origin": origin_str(&row.origin),
                "req_len": row.req_len,
                "resp_len": row.resp_len,
                "target_data": {"untrusted": true, "url": shown_url(&row.url, redact)},
            }),
            cfx_bridge::HistoryCursor {
                at_ms: row.at_ms,
                id: row.id,
            },
        ));
    }
    let tag = o.tag();
    let mut next = r.next.map(|at| Cursor::History { project: tag, at });
    let mut truncated = false;
    let build = |rows: &[(Value, cfx_bridge::HistoryCursor)], next: &Option<Cursor>, cut: bool| {
        json!({
            "workbench": o.shown(),
            "rows": rows.iter().map(|(v, _)| v.clone()).collect::<Vec<_>>(),
            "next_cursor": next.as_ref().map(|c| c.to_string()),
            "truncated": cut,
        })
    };
    let summary = |n: usize, more: bool| {
        format!(
            "{n} exchange(s) from project {} in the Workbench (pid {}), newest first{}.",
            o.name(),
            o.inst.pid,
            if more {
                "; pass next_cursor for more"
            } else {
                ""
            }
        )
    };
    let mut value = build(&rows, &next, truncated);
    // Rows are dropped from the end until the result fits, and the cursor then starts
    // after the last row kept, so nothing is skipped.
    while rows.len() > 1 && result_size(&summary(rows.len(), true), &value) > RESULT_CAP {
        rows.pop();
        truncated = true;
        next = rows.last().map(|(_, at)| Cursor::History {
            project: tag,
            at: *at,
        });
        value = build(&rows, &next, truncated);
    }
    note.result = Some(json!({"rows": rows.len()}));
    Ok(Done {
        summary: summary(rows.len(), next.is_some()),
        value,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExchangeArgs {
    exchange: String,
    #[serde(default)]
    include: Option<Vec<String>>,
    #[serde(default)]
    max_body_bytes: Option<u64>,
}

pub(crate) fn parse_handle(raw: &str) -> Result<ExchangeHandle, Refusal> {
    raw.parse::<ExchangeHandle>().map_err(|_| {
        Refusal::invalid(
            "exchange is not a handle this server gave out (wx_<10 hex>_<id>); take one from \
             workbench_list_history",
        )
    })
}

async fn get_exchange(
    mcp: &Mcp,
    args: &Value,
    ct: &CancellationToken,
    note: &mut CallNote,
) -> Result<Done, Refusal> {
    let a: ExchangeArgs = parse_args(args)?;
    let h = parse_handle(&a.exchange)?;
    let max = super::in_range(
        "max_body_bytes",
        a.max_body_bytes.unwrap_or(4096),
        1,
        32_768,
    )?;
    let mut parts = Vec::new();
    for p in a.include.unwrap_or_default() {
        let part = match p.as_str() {
            "request" => Part::Request,
            "response" => Part::Response,
            _ => return Err(Refusal::invalid("include holds request or response")),
        };
        if !parts.contains(&part) {
            parts.push(part);
        }
    }
    if parts.is_empty() {
        parts = vec![Part::Request, Part::Response];
    }
    let o = route(mcp, "workbench_get_exchange", None, Some(h.project)).await?;
    note.workbench = Some(o.audit());
    let x = read_exchange(&o, h.id, parts, max as u32, ct).await?;
    let summary = format!(
        "{} {} from project {}: HTTP {}.",
        untrusted::clean(&x.method, 32),
        untrusted::clean(&x.host, 200),
        o.name(),
        x.status
            .map_or_else(|| "no response".to_string(), |s| s.to_string())
    );
    let mut value = exchange_view(&o, &x, max as usize, mcp.settings.redact);
    fit(&summary, &mut value, &EXCHANGE_TEXTS, "/target_data");
    note.result = Some(json!({"status": x.status}));
    Ok(Done { value, summary })
}

pub(crate) async fn read_exchange(
    o: &Open,
    id: i64,
    parts: Vec<Part>,
    max_body_bytes: u32,
    ct: &CancellationToken,
) -> Result<ExchangeResult, Refusal> {
    let call = Call::Exchange(ExchangeParams {
        project_uid: o.project.uid.clone(),
        id,
        parts,
        max_body_bytes,
    });
    ask(o, &call, REQUEST_WAIT, ct)
        .await?
        .map_err(|e| bridge_refusal(e, o, "Nothing was read or sent."))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectionArgs {
    #[serde(default)]
    max_body_bytes: Option<u64>,
}

async fn get_selection(
    mcp: &Mcp,
    args: &Value,
    ct: &CancellationToken,
    note: &mut CallNote,
) -> Result<Done, Refusal> {
    let a: SelectionArgs = parse_args(args)?;
    let max = super::in_range(
        "max_body_bytes",
        a.max_body_bytes.unwrap_or(4096),
        1,
        32_768,
    )?;
    // The Workbench whose selection changed last. A single one is simply that one.
    let mut all = mcp.workbench.instances();
    if all.is_empty() {
        mcp.workbench.refresh().await;
        all = mcp.workbench.instances();
    }
    let latest = all
        .iter()
        .filter(|i| i.project().is_some())
        .filter(|i| {
            crate::workbench::needs("workbench_get_selection")
                .iter()
                .all(|m| i.welcome.supports(*m))
        })
        .max_by_key(|i| i.selection_ms())
        .and_then(|i| i.project())
        .map(|p| ProjectTag::of(&p.uid));
    let o = match latest {
        Some(Some(tag)) => route(mcp, "workbench_get_selection", None, Some(tag)).await?,
        _ => route(mcp, "workbench_get_selection", None, None).await?,
    };
    note.workbench = Some(o.audit());
    let sel: Option<SelectionResult> = ask(&o, &Call::Selection, REQUEST_WAIT, ct)
        .await?
        .map_err(|e| bridge_refusal(e, &o, "Nothing was read."))?;
    let redact = mcp.settings.redact;
    let Some(sel) = sel else {
        let value = json!({
            "workbench": o.shown(),
            "tool": "none",
            "selected": null,
            "repeater_draft": null,
        });
        note.result = Some(json!({"selected": false}));
        return Ok(Done {
            value,
            summary: format!("Nothing is selected in project {}.", o.name()),
        });
    };
    if sel.project_uid != o.project.uid {
        return Err(Refusal::new(
            Reason::ProjectChanged,
            format!(
                "The Workbench (pid {}) switched projects while it was being read. Nothing was \
                 read; call again.",
                o.inst.pid
            ),
        ));
    }
    let selected = match sel.exchange_id {
        Some(id) => {
            match read_exchange(&o, id, vec![Part::Request, Part::Response], max as u32, ct).await {
                Ok(x) => Some(exchange_view(&o, &x, max as usize, redact)),
                Err(r) if r.reason == Reason::NotFound => None,
                Err(r) => return Err(r),
            }
        }
        None => None,
    };
    let draft = sel.repeater.as_ref().map(|d| {
        let (text, cut) = untrusted::sanitize(&d.text, cfx_bridge::SELECTION_TEXT_MAX);
        let text = if redact {
            redact::redact_text(&text)
        } else {
            text
        };
        json!({
            "target": {
                "host": untrusted::clean(&d.target.host, 200),
                "port": d.target.port,
                "tls": d.target.tls,
            },
            "target_data": {"untrusted": true, "text": text, "truncated": d.truncated || cut},
        })
    });
    let tool = untrusted::clean(&sel.tool, 40);
    let summary = format!(
        "The Workbench (pid {}) shows {} in project {}{}{}.",
        o.inst.pid,
        if tool.is_empty() { "nothing" } else { &tool },
        o.name(),
        if selected.is_some() {
            ", with an exchange selected"
        } else {
            ""
        },
        if draft.is_some() {
            ", and a Repeater draft"
        } else {
            ""
        }
    );
    let mut value = json!({
        "workbench": o.shown(),
        "tool": tool,
        "selected": selected,
        "repeater_draft": draft,
    });
    fit(
        &summary,
        &mut value,
        &[
            "/selected/target_data/request/body/text",
            "/selected/target_data/response/body/text",
            "/repeater_draft/target_data/text",
        ],
        "/selected/target_data",
    );
    note.result = Some(json!({"selected": value["selected"].is_object()}));
    Ok(Done { value, summary })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SiteMapArgs {
    #[serde(default)]
    project: Option<String>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    limit: Option<u64>,
}

async fn get_site_map(
    mcp: &Mcp,
    args: &Value,
    ct: &CancellationToken,
    note: &mut CallNote,
) -> Result<Done, Refusal> {
    let a: SiteMapArgs = parse_args(args)?;
    max_len("project", &a.project, 200)?;
    max_len("host", &a.host, 253)?;
    max_len("cursor", &a.cursor, 9000)?;
    let limit = super::in_range("limit", a.limit.unwrap_or(100), 1, 200)? as u32;
    let cursor = parse_cursor(&a.cursor, false)?;
    let o = route(
        mcp,
        "workbench_get_site_map",
        a.project.as_deref(),
        cursor.as_ref().map(Cursor::project),
    )
    .await?;
    note.workbench = Some(o.audit());
    let call = Call::SiteMap(SiteMapParams {
        project_uid: o.project.uid.clone(),
        host: a.host.map(|h| h.trim().to_ascii_lowercase()),
        cursor: match cursor {
            Some(Cursor::SiteMap { at, .. }) => Some(at),
            _ => None,
        },
        limit,
    });
    let r: SiteMapResult = ask(&o, &call, REQUEST_WAIT, ct)
        .await?
        .map_err(|e| bridge_refusal(e, &o, "Nothing was read."))?;
    let redact = mcp.settings.redact;
    let shown_path = |p: &str| {
        let p = untrusted::clean(p, URL_MAX);
        if redact { redact::redact_text(&p) } else { p }
    };
    let mut rows: Vec<(Value, cfx_bridge::SiteMapCursor)> = r
        .endpoints
        .iter()
        .map(|e| {
            (
                json!({
                    "host": untrusted::clean(&e.host, 200),
                    "method": untrusted::clean(&e.method, 32),
                    "status": e.status,
                    "count": e.count,
                    "last_at": rfc3339(e.last_ms),
                    "has_query": e.has_query,
                    "target_data": {"untrusted": true, "path": shown_path(&e.path)},
                }),
                cfx_bridge::SiteMapCursor {
                    host: e.host.clone(),
                    path: e.path.clone(),
                    method: e.method.clone(),
                },
            )
        })
        .collect();
    let tag = o.tag();
    let mut next = r.next.map(|at| Cursor::SiteMap { project: tag, at });
    let mut truncated = false;
    let build = |rows: &[(Value, cfx_bridge::SiteMapCursor)], next: &Option<Cursor>, cut: bool| {
        json!({
            "workbench": o.shown(),
            "endpoints": rows.iter().map(|(v, _)| v.clone()).collect::<Vec<_>>(),
            "next_cursor": next.as_ref().map(|c| c.to_string()),
            "incomplete": r.incomplete,
            "truncated": cut,
        })
    };
    let summary = |n: usize, more: bool| {
        format!(
            "{n} endpoint(s) from project {} in the Workbench (pid {}){}{}.",
            o.name(),
            o.inst.pid,
            if more {
                "; pass next_cursor for more"
            } else {
                ""
            },
            if r.incomplete {
                "; the project holds more than the site map reads"
            } else {
                ""
            }
        )
    };
    let mut value = build(&rows, &next, truncated);
    while rows.len() > 1 && result_size(&summary(rows.len(), true), &value) > RESULT_CAP {
        rows.pop();
        truncated = true;
        next = rows.last().map(|(_, at)| Cursor::SiteMap {
            project: tag,
            at: at.clone(),
        });
        value = build(&rows, &next, truncated);
    }
    note.result = Some(json!({"endpoints": rows.len()}));
    Ok(Done {
        summary: summary(rows.len(), next.is_some()),
        value,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeArgs {
    #[serde(default)]
    project: Option<String>,
    #[serde(default)]
    targets: Option<Vec<String>>,
}

/// The rule every Workbench send follows, said for this project.
fn rule(restricted: bool, rules: usize) -> String {
    let both = "A workbench_* send goes out only to a destination that both the scope file \
                and the open project's scope admit.";
    if restricted {
        format!("{both} The project's scope has {rules} rule(s).")
    } else {
        format!(
            "{both} This project has no scope written, which admits everything, so the scope \
             file alone decides."
        )
    }
}

async fn get_scope(
    mcp: &Mcp,
    args: &Value,
    ct: &CancellationToken,
    note: &mut CallNote,
) -> Result<Done, Refusal> {
    let a: ScopeArgs = parse_args(args)?;
    max_len("project", &a.project, 200)?;
    let targets = a.targets.unwrap_or_default();
    if targets.len() > cfx_bridge::CHECK_DESTS_MAX {
        return Err(Refusal::invalid(format!(
            "targets holds at most {} entries",
            cfx_bridge::CHECK_DESTS_MAX
        )));
    }
    if targets.iter().any(|t| t.len() > guard::MAX_URL) {
        return Err(Refusal::invalid(format!(
            "a target is longer than {} bytes",
            guard::MAX_URL
        )));
    }
    let o = route(mcp, "workbench_get_scope", a.project.as_deref(), None).await?;
    note.workbench = Some(o.audit());
    let s: ScopeResult = ask(
        &o,
        &Call::Scope(ScopeParams {
            project_uid: o.project.uid.clone(),
        }),
        REQUEST_WAIT,
        ct,
    )
    .await?
    .map_err(|e| bridge_refusal(e, &o, "Nothing was read."))?;

    let parsed: Vec<(String, Result<guard::Dest, String>)> = targets
        .iter()
        .map(|t| (untrusted::clean(t.trim(), 200), guard::parse_target(t)))
        .collect();
    let dests: Vec<Dest> = parsed
        .iter()
        .filter_map(|(_, d)| d.as_ref().ok())
        .map(|d| Dest {
            host: d.host.clone(),
            port: d.port,
        })
        .collect();
    let answered: Vec<cfx_bridge::CheckRow> = if dests.is_empty() {
        Vec::new()
    } else {
        // A question, so nothing is recorded in the project's refusal log.
        let r: CheckResult = ask(
            &o,
            &Call::Check(CheckParams {
                project_uid: o.project.uid.clone(),
                dests,
                record: false,
                detail: None,
            }),
            REQUEST_WAIT,
            ct,
        )
        .await?
        .map_err(|e| bridge_refusal(e, &o, "Nothing was read."))?;
        r.results
    };
    let checks: Vec<Value> = parsed
        .iter()
        .map(|(input, d)| match d {
            Ok(d) => {
                let mcp_ok = mcp.scope.scope.admits(&d.host, Some(d.port));
                let wb_ok = answered
                    .iter()
                    .find(|r| r.host == d.host && r.port == d.port)
                    .is_some_and(|r| r.admitted);
                json!({
                    "target": input,
                    "host": untrusted::clean(&d.host, 200),
                    "port": d.port,
                    "mcp_admitted": mcp_ok,
                    "workbench_admitted": wb_ok,
                    "admitted": mcp_ok && wb_ok,
                })
            }
            Err(e) => json!({
                "target": input,
                "error": untrusted::clean(e, 200),
                "mcp_admitted": false,
                "workbench_admitted": false,
                "admitted": false,
            }),
        })
        .collect();
    let recent: Vec<Value> = s
        .recent
        .iter()
        .take(20)
        .map(|r| {
            json!({
                "at": rfc3339(r.at_ms),
                "host": untrusted::clean(&r.host, 200),
                "port": r.port,
                "point": untrusted::clean(&r.point, 40),
                "detail": r.detail.as_deref().map(|d| untrusted::clean(d, 200)),
            })
        })
        .collect();
    let entries: Vec<String> = s
        .entries
        .iter()
        .take(500)
        .map(|e| untrusted::clean(e, 200))
        .collect();
    let value = json!({
        "workbench": o.shown(),
        "project_scope": {
            "restricted": s.restricted,
            "entries": entries,
            "rejected": s.rejected.iter().take(100).map(|e| untrusted::clean(e, 200)).collect::<Vec<_>>(),
            "refused_total": s.refused_total,
            "refusals_dropped": s.refusals_dropped,
        },
        "mcp_scope": {
            "sha256": mcp.scope.sha256,
            "entries": mcp.scope.entries,
        },
        "rule": rule(s.restricted, s.entries.len()),
        "checks": checks,
        "target_data": {"untrusted": true, "recent_refusals": recent},
    });
    let admitted = checks.iter().filter(|c| c["admitted"] == true).count();
    let summary = format!(
        "Project {} scope: {}; the scope file has {} entries.{}",
        o.name(),
        if s.restricted {
            format!("{} rule(s)", s.entries.len())
        } else {
            "none written".into()
        },
        mcp.scope.entries.len(),
        if checks.is_empty() {
            String::new()
        } else {
            format!(
                " {admitted} of {} target(s) are admitted by both.",
                checks.len()
            )
        }
    );
    note.result = Some(json!({"restricted": s.restricted, "checks": checks.len()}));
    Ok(Done { value, summary })
}

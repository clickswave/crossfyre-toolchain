//! One params and one result type per method, and [`Call`], a request with its type.
//!
//! Exchange ids here are the ids a project gives its exchanges. The `wx_` handles an
//! agent sees are made from them on the MCP side, with [`crate::ExchangeHandle`].

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::{
    Edits, ErrorBody, ErrorCode, ProjectInfo, Request, is_project_uid, open_enum, required,
};

/// `history` returns at most this many rows.
pub const HISTORY_LIMIT_MAX: u32 = 100;
/// `site_map` returns at most this many rows.
pub const SITE_MAP_LIMIT_MAX: u32 = 200;
/// The most body bytes `exchange` and `replay` return per side.
pub const BODY_BYTES_MAX: u32 = 32 * 1024;
/// `check` takes at most this many destinations.
pub const CHECK_DESTS_MAX: usize = 50;
/// `replay` takes between one and this many pinned addresses.
pub const PINS_MAX: usize = 8;
/// `scan_source` refuses a body larger than this with `too_large`.
pub const SCAN_SOURCE_BODY_MAX: usize = 64 * 1024;
/// The Repeater text `selection` returns is cut at this many bytes.
pub const SELECTION_TEXT_MAX: usize = 16 * 1024;
/// The longest `label` and `detail`.
pub const LABEL_MAX: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    Status,
    History,
    Exchange,
    Selection,
    SiteMap,
    Scope,
    Check,
    Replay,
    ScanSource,
    Cancel,
}

impl Method {
    pub const ALL: [Method; 10] = [
        Method::Status,
        Method::History,
        Method::Exchange,
        Method::Selection,
        Method::SiteMap,
        Method::Scope,
        Method::Check,
        Method::Replay,
        Method::ScanSource,
        Method::Cancel,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Method::Status => "status",
            Method::History => "history",
            Method::Exchange => "exchange",
            Method::Selection => "selection",
            Method::SiteMap => "site_map",
            Method::Scope => "scope",
            Method::Check => "check",
            Method::Replay => "replay",
            Method::ScanSource => "scan_source",
            Method::Cancel => "cancel",
        }
    }

    pub fn parse(s: &str) -> Option<Method> {
        Method::ALL.into_iter().find(|m| m.as_str() == s)
    }
}

/// A request with its params typed and checked.
#[derive(Debug, Clone, PartialEq)]
pub enum Call {
    Status,
    History(HistoryParams),
    Exchange(ExchangeParams),
    Selection,
    SiteMap(SiteMapParams),
    Scope(ScopeParams),
    Check(CheckParams),
    Replay(ReplayParams),
    ScanSource(ScanSourceParams),
    Cancel(CancelParams),
}

impl Call {
    pub fn method(&self) -> Method {
        match self {
            Call::Status => Method::Status,
            Call::History(_) => Method::History,
            Call::Exchange(_) => Method::Exchange,
            Call::Selection => Method::Selection,
            Call::SiteMap(_) => Method::SiteMap,
            Call::Scope(_) => Method::Scope,
            Call::Check(_) => Method::Check,
            Call::Replay(_) => Method::Replay,
            Call::ScanSource(_) => Method::ScanSource,
            Call::Cancel(_) => Method::Cancel,
        }
    }

    /// The project the call is for. Every method but `status`, `selection` and `cancel`
    /// names one, and the server answers `project_changed` when it is not the open one.
    pub fn project_uid(&self) -> Option<&str> {
        match self {
            Call::Status | Call::Selection | Call::Cancel(_) => None,
            Call::History(p) => Some(&p.project_uid),
            Call::Exchange(p) => Some(&p.project_uid),
            Call::SiteMap(p) => Some(&p.project_uid),
            Call::Scope(p) => Some(&p.project_uid),
            Call::Check(p) => Some(&p.project_uid),
            Call::Replay(p) => Some(&p.project_uid),
            Call::ScanSource(p) => Some(&p.project_uid),
        }
    }

    /// The request line, newline included, with the params in their fields' order.
    pub fn to_line(&self, id: u64) -> String {
        #[derive(Serialize)]
        struct Line<'a, P> {
            id: u64,
            method: &'static str,
            #[serde(skip_serializing_if = "Option::is_none")]
            params: Option<&'a P>,
        }
        fn line<P: Serialize>(id: u64, m: Method, params: Option<&P>) -> String {
            crate::to_line(&Line {
                id,
                method: m.as_str(),
                params,
            })
        }
        let m = self.method();
        match self {
            Call::Status | Call::Selection => line::<()>(id, m, None),
            Call::History(p) => line(id, m, Some(p)),
            Call::Exchange(p) => line(id, m, Some(p)),
            Call::SiteMap(p) => line(id, m, Some(p)),
            Call::Scope(p) => line(id, m, Some(p)),
            Call::Check(p) => line(id, m, Some(p)),
            Call::Replay(p) => line(id, m, Some(p)),
            Call::ScanSource(p) => line(id, m, Some(p)),
            Call::Cancel(p) => line(id, m, Some(p)),
        }
    }

    /// Type a request and check its params against the protocol's limits.
    ///
    /// The error is what the server sends back: `unsupported_method` for a method it
    /// does not know, `invalid_params` for anything wrong with the params.
    pub fn from_request(r: &Request) -> Result<Call, ErrorBody> {
        let Some(m) = Method::parse(&r.method) else {
            return Err(ErrorBody::new(
                ErrorCode::UnsupportedMethod,
                format!("unknown method {:?}", r.method),
            ));
        };
        fn typed<T: serde::de::DeserializeOwned>(
            p: &Option<Box<RawValue>>,
        ) -> Result<T, ErrorBody> {
            serde_json::from_str(p.as_deref().map_or("null", RawValue::get))
                .map_err(|e| ErrorBody::new(ErrorCode::InvalidParams, e.to_string()))
        }
        let call = match m {
            Method::Status => Call::Status,
            Method::Selection => Call::Selection,
            Method::History => Call::History(typed(&r.params)?),
            Method::Exchange => Call::Exchange(typed(&r.params)?),
            Method::SiteMap => Call::SiteMap(typed(&r.params)?),
            Method::Scope => Call::Scope(typed(&r.params)?),
            Method::Check => Call::Check(typed(&r.params)?),
            Method::Replay => Call::Replay(typed(&r.params)?),
            Method::ScanSource => Call::ScanSource(typed(&r.params)?),
            Method::Cancel => Call::Cancel(typed(&r.params)?),
        };
        call.validate()
            .map_err(|m| ErrorBody::new(ErrorCode::InvalidParams, m))?;
        Ok(call)
    }

    /// The limits in the protocol, which the server enforces and a client can check
    /// before it sends.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(uid) = self.project_uid() {
            if !is_project_uid(uid) {
                return Err("project_uid is not 32 lowercase hex characters".into());
            }
        }
        match self {
            Call::History(p) => {
                in_range("limit", p.limit, 1, HISTORY_LIMIT_MAX)?;
                if let (Some(lo), Some(hi)) = (p.filter.status_min, p.filter.status_max) {
                    if lo > hi {
                        return Err("status_min is above status_max".into());
                    }
                }
                Ok(())
            }
            Call::Exchange(p) => in_range("max_body_bytes", p.max_body_bytes, 0, BODY_BYTES_MAX),
            Call::SiteMap(p) => in_range("limit", p.limit, 1, SITE_MAP_LIMIT_MAX),
            Call::Check(p) => {
                if p.dests.len() > CHECK_DESTS_MAX {
                    return Err(format!("at most {CHECK_DESTS_MAX} destinations"));
                }
                if p.dests.iter().any(|d| d.host.is_empty()) {
                    return Err("a destination has no host".into());
                }
                label("detail", p.detail.as_deref().unwrap_or(""))
            }
            Call::Replay(p) => {
                if p.pins.is_empty() || p.pins.len() > PINS_MAX {
                    return Err(format!("between 1 and {PINS_MAX} pins"));
                }
                if p.label.is_empty() {
                    return Err("label is empty".into());
                }
                label("label", &p.label)?;
                in_range("max_body_bytes", p.max_body_bytes, 0, BODY_BYTES_MAX)?;
                p.edits.validate()
            }
            Call::Status
            | Call::Selection
            | Call::Scope(_)
            | Call::ScanSource(_)
            | Call::Cancel(_) => Ok(()),
        }
    }
}

fn in_range(name: &str, v: u32, lo: u32, hi: u32) -> Result<(), String> {
    if v < lo || v > hi {
        return Err(format!("{name} is {v}, and has to be {lo} to {hi}"));
    }
    Ok(())
}

fn label(name: &str, v: &str) -> Result<(), String> {
    if v.len() > LABEL_MAX {
        return Err(format!("{name} is longer than {LABEL_MAX} bytes"));
    }
    if v.chars().any(char::is_control) {
        return Err(format!("{name} has a control character"));
    }
    Ok(())
}

/// Headers in the order they were sent, as `[[name, value], ...]`.
pub type Headers = Vec<(String, String)>;

open_enum! {
    /// How an exchange came to be in the project.
    Origin {
        /// Through the capture proxy.
        Proxy = "proxy",
        Repeater = "repeater",
        Replay = "replay",
        /// Sent for an agent, through this bridge.
        Agent = "agent",
    }
}

// ----- status -----

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusResult {
    #[serde(deserialize_with = "required")]
    pub project: Option<ProjectInfo>,
    /// `None` while the proxy is stopped.
    pub proxy_port: Option<u16>,
    pub intercepting: bool,
    pub scope: ScopeSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeSummary {
    /// `false` when nothing is written down, so everything is carried.
    pub restricted: bool,
    /// The rules in force. Zero with `restricted` means every entry was refused.
    pub rules: u64,
}

// ----- history -----

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryParams {
    pub project_uid: String,
    #[serde(default)]
    pub filter: HistoryFilter,
    /// Rows strictly older than this, newest first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<HistoryCursor>,
    pub limit: u32,
}

/// Every field narrows. An empty filter is every row.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_min: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_max: Option<u16>,
    /// Any of these. Empty is all.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub origins: Vec<Origin>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_contains: Option<String>,
    /// Full-text search over the stored exchange.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until_ms: Option<i64>,
}

/// Where a history page ends: the last row's time and id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HistoryCursor {
    pub at_ms: i64,
    pub id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryResult {
    pub rows: Vec<HistoryRow>,
    /// `None` on the last page.
    pub next: Option<HistoryCursor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryRow {
    pub id: i64,
    pub at_ms: i64,
    pub method: String,
    pub url: String,
    pub host: String,
    /// `None` when no response came back.
    pub status: Option<u16>,
    pub req_len: u64,
    pub resp_len: u64,
    pub pinned: bool,
    pub origin: Origin,
    /// For an agent row, the name the client gave.
    pub actor: Option<String>,
}

// ----- exchange -----

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Part {
    Request,
    Response,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExchangeParams {
    pub project_uid: String,
    pub id: i64,
    pub parts: Vec<Part>,
    /// Per body, 0 to [`BODY_BYTES_MAX`]. Zero returns the length and no text.
    pub max_body_bytes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExchangeResult {
    pub id: i64,
    pub at_ms: i64,
    pub method: String,
    pub url: String,
    pub host: String,
    pub status: Option<u16>,
    pub duration_ms: Option<u64>,
    pub origin: Origin,
    pub actor: Option<String>,
    pub pinned: bool,
    /// Absent when the request part was not asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub req_headers: Option<Headers>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resp_headers: Option<Headers>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub req_body: Option<Body>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resp_body: Option<Body>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Encoding {
    Text,
    Binary,
}

/// A body, cut to what was asked for. Binary bodies carry no text, only their first
/// bytes as hex, which is enough to tell a PNG from a protobuf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Body {
    pub encoding: Encoding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub magic_hex: Option<String>,
    /// The whole body's length, however much of it is here.
    pub len: u64,
    pub truncated: bool,
}

impl Body {
    /// How many leading bytes of a binary body are shown.
    pub const MAGIC_BYTES: usize = 16;

    /// `len` is the whole body's length in bytes, and `truncated` says whether `text` is
    /// less than all of it. The caller says so rather than this comparing lengths,
    /// because decoding can change how long the text is.
    pub fn text(text: String, len: u64, truncated: bool) -> Body {
        Body {
            encoding: Encoding::Text,
            text: Some(text),
            magic_hex: None,
            len,
            truncated,
        }
    }

    /// `head` is the start of the body, of which the first [`Body::MAGIC_BYTES`] are kept.
    pub fn binary(head: &[u8], len: u64) -> Body {
        let shown = &head[..head.len().min(Self::MAGIC_BYTES)];
        Body {
            encoding: Encoding::Binary,
            text: None,
            magic_hex: Some(shown.iter().map(|b| format!("{b:02x}")).collect()),
            len,
            truncated: (shown.len() as u64) < len,
        }
    }
}

// ----- selection -----

/// What the operator has in front of them. The result of `selection`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectionResult {
    pub project_uid: String,
    pub changed_ms: i64,
    /// Which part of the window is showing.
    pub tool: String,
    pub exchange_id: Option<i64>,
    pub repeater: Option<RepeaterDraft>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepeaterDraft {
    pub target: Target,
    /// Up to [`SELECTION_TEXT_MAX`] bytes.
    pub text: String,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub tls: bool,
}

// ----- site_map -----

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteMapParams {
    pub project_uid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Rows after this one, in (host, path, method) order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<SiteMapCursor>,
    pub limit: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SiteMapCursor {
    pub host: String,
    pub path: String,
    pub method: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteMapResult {
    pub endpoints: Vec<SiteMapRow>,
    pub next: Option<SiteMapCursor>,
    /// The project has more groups than the site map reads, so this is not all of it.
    pub incomplete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteMapRow {
    pub host: String,
    pub path: String,
    pub method: String,
    pub status: Option<u16>,
    pub count: u64,
    pub last_ms: i64,
    pub bytes: u64,
    pub has_query: bool,
}

// ----- scope -----

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeParams {
    pub project_uid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeResult {
    pub restricted: bool,
    pub entries: Vec<String>,
    /// Entries written down that did not parse, and so admit nothing.
    pub rejected: Vec<String>,
    pub refused_total: u64,
    /// Refusals the project could not store.
    pub refusals_dropped: u64,
    /// Newest first, at most 20.
    pub recent: Vec<RefusalRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefusalRow {
    pub at_ms: i64,
    pub host: String,
    pub port: u16,
    /// Where it was refused, as the scope crate's `Point::as_str` writes it.
    pub point: String,
    pub detail: Option<String>,
}

// ----- check -----

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckParams {
    pub project_uid: String,
    pub dests: Vec<Dest>,
    /// Write a refusal to the project's refusal log, as a send would.
    pub record: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Dest {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckResult {
    pub results: Vec<CheckRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckRow {
    pub host: String,
    pub port: u16,
    pub admitted: bool,
}

// ----- replay -----

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplayParams {
    pub project_uid: String,
    pub id: i64,
    #[serde(default, skip_serializing_if = "Edits::is_empty")]
    pub edits: Edits,
    /// The addresses the MCP side cleared for the host, as `ip:port`. The server dials
    /// one its own lookup also gives, or answers `pin_mismatch`.
    pub pins: Vec<SocketAddr>,
    /// Who asked, recorded as the new row's actor.
    pub label: String,
    pub mcp: McpRef,
    pub max_body_bytes: u32,
}

/// The MCP call this send belongs to, so the project row and the MCP audit line can be
/// matched up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpRef {
    pub session: String,
    pub seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayResult {
    /// The new row the send was recorded as.
    pub new_id: i64,
    pub status: Option<u16>,
    pub duration_ms: u64,
    pub bytes: u64,
    pub request_line: String,
    /// What each edit did, in words.
    pub applied: Vec<String>,
    pub resp_headers: Headers,
    pub resp_body: Option<Body>,
}

// ----- scan_source -----

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanSourceParams {
    pub project_uid: String,
    pub id: i64,
}

/// A stored request, whole, for an injection test to be built from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanSourceResult {
    pub method: String,
    pub url: String,
    pub req_headers: Headers,
    /// UTF-8, at most [`SCAN_SOURCE_BODY_MAX`] bytes. `None` when there is no body.
    pub body: Option<String>,
    pub content_type: Option<String>,
}

// ----- cancel -----

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancelParams {
    /// A request id on this connection.
    pub id: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancelResult {}

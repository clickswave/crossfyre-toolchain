//! The Cloud API that `crossfyre mcp` calls, as both ends see it.
//!
//! Every route is a `POST` to `<api_url>/api/v1/mcp/<route>` with a JSON body and the
//! key in `Authorization: Bearer cfm_...`. Every answer is an [`Envelope`]: the HTTP
//! status repeated, a message for a person, a list of errors, and `data`. A refusal puts
//! its code in `data.reason` (a [`Refusal`]), so a client never has to read a sentence
//! to decide what happened.
//!
//! The key names one workspace. No request carries a workspace id, and every id a
//! request does carry is a raw UUID that the platform looks up inside the key's
//! workspace, so an id from anywhere else is `not_found`, the same answer as an id that
//! does not exist. The client shows those UUIDs to a model with a prefix that says what
//! they are ([`IdKind`]), and strips it again before they go back on the wire.
//!
//! What is here is what an open client already shows on the wire: shapes, limits and
//! codes. How the platform picks nodes, splits work or paces a scan is not part of it.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Where the routes live under the API origin.
pub const PATH: &str = "/api/v1/mcp/";

/// The routes, each appended to [`PATH`].
pub mod route {
    pub const WHOAMI: &str = "whoami";
    pub const SCOPE_LIST: &str = "scope/list";
    pub const SCOPE_CHECK: &str = "scope/check";
    pub const NODES_LIST: &str = "nodes/list";
    pub const SCANS_LIST: &str = "scans/list";
    pub const SCANS_GET: &str = "scans/get";
    pub const SCANS_RESULTS: &str = "scans/results";
    pub const RESULTS_GET: &str = "results/get";
    pub const VERDICTS_LIST: &str = "verdicts/list";
    pub const VERDICTS_GET: &str = "verdicts/get";
    pub const ASSETS_LIST: &str = "assets/list";
    pub const ASSETS_GET: &str = "assets/get";
    pub const SCANS_START: &str = "scans/start";
    pub const SCANS_CANCEL: &str = "scans/cancel";
    pub const APPROVALS_GET: &str = "approvals/get";
    pub const APPROVALS_WAIT: &str = "approvals/wait";
    pub const APPROVALS_DECIDE: &str = "approvals/decide";
    pub const KEY_REVOKE: &str = "key/revoke";

    /// Every route, for a proxy that forwards only these.
    pub const ALL: [&str; 18] = [
        WHOAMI,
        SCOPE_LIST,
        SCOPE_CHECK,
        NODES_LIST,
        SCANS_LIST,
        SCANS_GET,
        SCANS_RESULTS,
        RESULTS_GET,
        VERDICTS_LIST,
        VERDICTS_GET,
        ASSETS_LIST,
        ASSETS_GET,
        SCANS_START,
        SCANS_CANCEL,
        APPROVALS_GET,
        APPROVALS_WAIT,
        APPROVALS_DECIDE,
        KEY_REVOKE,
    ];

    /// The routes a `read` key is refused with `permission_denied`.
    pub const LAUNCH_ONLY: [&str; 2] = [SCANS_START, SCANS_CANCEL];
}

/// Headers the client sends besides `Authorization`, and the two the platform sends
/// back. What the client sends is recorded against the call and believed by nobody: any
/// client can say anything.
pub mod header {
    /// The MCP client's own name and version.
    pub const CLIENT: &str = "x-crossfyre-mcp-client";
    /// The local server's session id, so calls from one process can be grouped.
    pub const SESSION: &str = "x-crossfyre-mcp-session";
    /// The tool the call was made for.
    pub const TOOL: &str = "x-crossfyre-mcp-tool";
    /// sha256 of the local scope file, or `none`.
    pub const LOCAL_SCOPE: &str = "x-crossfyre-local-scope";
    /// On every answer: the id of the platform's record of this call.
    pub const CALL_ID: &str = "x-crossfyre-call-id";
    /// On a 429: seconds to wait.
    pub const RETRY_AFTER: &str = "retry-after";
    /// Each header value the client sends is cut to this many characters.
    pub const VALUE_MAX: usize = 64;
}

/// An MCP key: `cfm_` and 32 lowercase hex characters.
pub const KEY_PREFIX: &str = "cfm_";

pub fn valid_key(key: &str) -> bool {
    key.strip_prefix(KEY_PREFIX)
        .is_some_and(|h| h.len() == 32 && h.bytes().all(is_lower_hex))
}

/// What a key shows of itself: `cfm_` and its first 8 hex characters.
pub fn key_prefix(key: &str) -> Option<String> {
    valid_key(key).then(|| key[..KEY_PREFIX.len() + 8].to_string())
}

/// The longest `approvals/wait` holds a request open. Kept under the origin timeout of
/// the proxy in front of the API.
pub const MAX_WAIT_SECONDS: u32 = 25;
/// Targets in one `scope/check`.
pub const MAX_CHECK_TARGETS: usize = 100;
/// Rows in one page of `scans/list`, `verdicts/list` and `assets/list`.
pub const MAX_LIST_LIMIT: u32 = 50;
/// Rows in one page of `scans/results`.
pub const MAX_RESULTS_LIMIT: u32 = 100;
/// The most of one result's `data`, or one verdict's evidence, an answer carries.
pub const MAX_ROW_BYTES: usize = 32 * 1024;
/// How long an approval waits for a person.
pub const APPROVAL_MINUTES: u32 = 10;

fn is_lower_hex(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
}

/// The words a client keeps at the top of a result. A value outside these reaches a
/// model as `other`, with the text moved under `target_data`, because a status or a
/// kind is where a field written by a scanned system would otherwise pass for the
/// platform's own.
pub mod vocab {
    pub const SCAN_STATUSES: [&str; 10] = [
        "pending",
        "populating",
        "queued",
        "running",
        "completed",
        "failed",
        "halted",
        "stopped",
        "cancelled",
        "awaiting_approval",
    ];
    /// The scan statuses after which nothing more happens.
    pub const SCAN_ENDED: [&str; 5] = ["completed", "failed", "halted", "stopped", "cancelled"];
    pub const VERDICT_STATUSES: [&str; 9] = [
        "open",
        "triaged",
        "confirmed",
        "false_positive",
        "accepted",
        "fixed",
        "resolved",
        "reopened",
        "ignored",
    ];
    pub const ASSET_STATUSES: [&str; 5] = ["active", "inactive", "new", "gone", "archived"];
    pub const NODE_STATUSES: [&str; 6] = [
        "online",
        "offline",
        "busy",
        "provisioning",
        "error",
        "maintenance",
    ];
    pub const CONFIDENCES: [&str; 7] = [
        "tentative",
        "firm",
        "certain",
        "low",
        "medium",
        "high",
        "confirmed",
    ];
    /// How a scan was started: `created_via`.
    pub const CHANNELS: [&str; 6] = ["dashboard", "cli", "mcp", "valkyrie", "mobile", "system"];

    /// A type, kind, source, engine or phase: a lowercase word of letters, digits and
    /// `_`, `.` or `-`, at most 64 characters, starting with a letter or digit.
    pub fn is_word(s: &str) -> bool {
        let b = s.as_bytes();
        !b.is_empty()
            && b.len() <= 64
            && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
            && b.iter().all(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'.' | b'-')
            })
    }
}

// ---------------------------------------------------------------------------
// The envelope and refusals

/// Every answer, success or refusal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope<T> {
    pub status: u16,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub errors: Vec<String>,
    pub data: T,
}

/// Why the platform did not do what a call asked. The string forms are the codes in
/// `data.reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// The Cloud side is switched off. 404.
    McpDisabled,
    /// No key, a malformed one, or one the platform does not know. 401.
    KeyInvalid,
    KeyRevoked,
    KeyExpired,
    /// 403, from the account checks the platform makes on every key.
    AccountSuspended,
    EmailUnverified,
    /// The key's owner is no longer in the workspace. 403.
    NotAMember,
    WorkspaceArchived,
    WorkspaceSuspended,
    /// A `read` key on a launch route. 403.
    PermissionDenied,
    /// Over the per-key call or launch limit. 429, with `Retry-After`.
    RateLimited,
    /// Over the number of scans one key may have running. 429.
    ScanLimit,
    /// The workspace's scope list is empty. 403.
    ScopeEmpty,
    /// None of the workspace's current entries is one the key's owner confirmed when
    /// the key was made. 403.
    ScopeNotAttested,
    /// A target is outside the entries the key may launch against. 403, with `refused`.
    OutOfScope,
    /// A named node is not in the workspace, not online, or lacks the engine. 400.
    NodeUnavailable,
    /// No node was named and none is online with the engine. 409.
    NoOnlineNode,
    PlanLimit,
    /// The plan does not include this kind of scan. 402, with `feature`.
    PlanFeature,
    DemoWorkspace,
    StartFailed,
    /// Absent, or in another workspace. 404.
    NotFound,
    NotRunning,
    /// The approval was decided already. 409.
    AlreadyDecided,
    /// The approval waited past its expiry. 409.
    ApprovalExpired,
    /// The launch needs a person's approval, the key's owner has no phone registered,
    /// and the workspace does not allow the agent's own client to ask. 403.
    ApprovalRequired,
    /// `approvals/decide` from the agent's client on an approval that only a phone can
    /// approve. 403.
    ElicitationNotAllowed,
    /// The platform could not record the call, so it did not act on it. 503.
    AuditUnavailable,
    InvalidArguments,
    Internal,
    /// A code this version does not know.
    #[serde(other)]
    Other,
}

impl Reason {
    pub const ALL: [Reason; 30] = [
        Reason::McpDisabled,
        Reason::KeyInvalid,
        Reason::KeyRevoked,
        Reason::KeyExpired,
        Reason::AccountSuspended,
        Reason::EmailUnverified,
        Reason::NotAMember,
        Reason::WorkspaceArchived,
        Reason::WorkspaceSuspended,
        Reason::PermissionDenied,
        Reason::RateLimited,
        Reason::ScanLimit,
        Reason::ScopeEmpty,
        Reason::ScopeNotAttested,
        Reason::OutOfScope,
        Reason::NodeUnavailable,
        Reason::NoOnlineNode,
        Reason::PlanLimit,
        Reason::PlanFeature,
        Reason::DemoWorkspace,
        Reason::StartFailed,
        Reason::NotFound,
        Reason::NotRunning,
        Reason::AlreadyDecided,
        Reason::ApprovalExpired,
        Reason::ApprovalRequired,
        Reason::ElicitationNotAllowed,
        Reason::AuditUnavailable,
        Reason::InvalidArguments,
        Reason::Internal,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Reason::McpDisabled => "mcp_disabled",
            Reason::KeyInvalid => "key_invalid",
            Reason::KeyRevoked => "key_revoked",
            Reason::KeyExpired => "key_expired",
            Reason::AccountSuspended => "account_suspended",
            Reason::EmailUnverified => "email_unverified",
            Reason::NotAMember => "not_a_member",
            Reason::WorkspaceArchived => "workspace_archived",
            Reason::WorkspaceSuspended => "workspace_suspended",
            Reason::PermissionDenied => "permission_denied",
            Reason::RateLimited => "rate_limited",
            Reason::ScanLimit => "scan_limit",
            Reason::ScopeEmpty => "scope_empty",
            Reason::ScopeNotAttested => "scope_not_attested",
            Reason::OutOfScope => "out_of_scope",
            Reason::NodeUnavailable => "node_unavailable",
            Reason::NoOnlineNode => "no_online_node",
            Reason::PlanLimit => "plan_limit",
            Reason::PlanFeature => "plan_feature",
            Reason::DemoWorkspace => "demo_workspace",
            Reason::StartFailed => "start_failed",
            Reason::NotFound => "not_found",
            Reason::NotRunning => "not_running",
            Reason::AlreadyDecided => "already_decided",
            Reason::ApprovalExpired => "approval_expired",
            Reason::ApprovalRequired => "approval_required",
            Reason::ElicitationNotAllowed => "elicitation_not_allowed",
            Reason::AuditUnavailable => "audit_unavailable",
            Reason::InvalidArguments => "invalid_arguments",
            Reason::Internal => "internal",
            Reason::Other => "other",
        }
    }

    /// A code read from the wire. Unknown text is [`Reason::Other`], never an error.
    pub fn parse(s: &str) -> Reason {
        Reason::ALL
            .into_iter()
            .find(|r| r.as_str() == s)
            .unwrap_or(Reason::Other)
    }

    /// The key itself was refused, so no other call with it will work either.
    pub fn rejects_key(self) -> bool {
        matches!(
            self,
            Reason::KeyInvalid | Reason::KeyRevoked | Reason::KeyExpired
        )
    }
}

/// `data` of a refusal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Refusal {
    pub reason: Reason,
    /// For `out_of_scope`: every target that was refused, not just the first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refused: Vec<RefusedTarget>,
    /// For `node_unavailable`: the node ids that could not be used.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nodes: Vec<String>,
    /// For `plan_feature`: what the plan lacks, such as `authz_engine`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feature: Option<String>,
}

impl Refusal {
    pub fn new(reason: Reason) -> Self {
        Refusal {
            reason,
            refused: Vec::new(),
            nodes: Vec::new(),
            feature: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefusedTarget {
    /// As the request gave it.
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

// ---------------------------------------------------------------------------
// Ids

/// What a Cloud id names. The client shows each as its prefix and the UUID's 32 hex
/// digits, so a model can tell a Cloud scan from a local one (`s_` and 10 hex) by
/// looking at it, and so a server can refuse an id given to the wrong tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdKind {
    /// A workflow. `cs_`
    Scan,
    /// A row of a scan's results. `cf_`
    Result,
    /// A workspace verdict on an asset. `cv_`
    Verdict,
    /// `ca_`
    Asset,
    /// `cn_`
    Node,
    /// A launch waiting for a person. `ap_`
    Approval,
}

impl IdKind {
    pub const ALL: [IdKind; 6] = [
        IdKind::Scan,
        IdKind::Result,
        IdKind::Verdict,
        IdKind::Asset,
        IdKind::Node,
        IdKind::Approval,
    ];

    pub fn prefix(self) -> &'static str {
        match self {
            IdKind::Scan => "cs_",
            IdKind::Result => "cf_",
            IdKind::Verdict => "cv_",
            IdKind::Asset => "ca_",
            IdKind::Node => "cn_",
            IdKind::Approval => "ap_",
        }
    }
}

/// A UUID as the platform writes one: 8-4-4-4-12 hex digits, either case.
pub fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// The client's form of a platform UUID, or `None` when it is not one.
pub fn encode(kind: IdKind, uuid: &str) -> Option<String> {
    if !is_uuid(uuid) {
        return None;
    }
    let hex: String = uuid
        .chars()
        .filter(|c| *c != '-')
        .map(|c| c.to_ascii_lowercase())
        .collect();
    Some(format!("{}{hex}", kind.prefix()))
}

/// What a client id names and the UUID it stands for, or `None` when it is not one of
/// these forms. Only lowercase hex is accepted, as [`encode`] writes it.
pub fn decode(id: &str) -> Option<(IdKind, String)> {
    let kind = IdKind::ALL
        .into_iter()
        .find(|k| id.starts_with(k.prefix()))?;
    let hex = &id[kind.prefix().len()..];
    if hex.len() != 32 || !hex.bytes().all(is_lower_hex) {
        return None;
    }
    let uuid = format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    );
    Some((kind, uuid))
}

// ---------------------------------------------------------------------------
// Requests and answers, route by route

/// The body of a route that takes nothing: `whoami`, `scope/list`, `key/revoke`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Empty {}

/// The body of a route that takes one id: `scans/get`, `results/get`, `assets/get`,
/// `approvals/get`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdRequest {
    pub id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// Scans, results, verdicts, assets, nodes and the scope.
    Read,
    /// Also start and stop scans on the workspace's nodes.
    Launch,
    #[serde(other)]
    Other,
}

impl Permission {
    pub fn as_str(self) -> &'static str {
        match self {
            Permission::Read => "read",
            Permission::Launch => "launch",
            Permission::Other => "other",
        }
    }
}

/// `whoami`: who the key belongs to, what it may do, and against what.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Whoami {
    pub key: KeyInfo,
    pub user: UserInfo,
    pub workspace: WorkspaceInfo,
    /// The plan's name, for a person to read.
    #[serde(default)]
    pub plan: String,
    pub limits: Limits,
    pub approval: ApprovalPolicy,
    pub scope: ScopeSummary,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyInfo {
    pub id: String,
    /// `cfm_` and 8 hex characters. Never the key.
    pub prefix: String,
    pub name: String,
    pub permission: Permission,
    /// RFC 3339.
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: String,
    pub username: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkspaceInfo {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Limits {
    pub running_workflows: u32,
    /// `None` when the plan sets no cap.
    pub max_concurrent_workflows: Option<u32>,
    pub monthly_used: u32,
    pub monthly_cap: Option<u32>,
    /// Launches and approval requests this key has left in the current hour.
    pub launches_left_this_hour: u32,
    /// Scans one key may have running at once.
    pub key_concurrent_cap: u32,
}

/// When a launch waits for a person, as the workspace sets it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    /// Only a launch that reaches more than one node, or that can write, and only when
    /// the key's owner has a phone registered to approve it.
    Risky,
    /// Every launch.
    Always,
    #[serde(other)]
    Other,
}

impl ApprovalMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ApprovalMode::Risky => "risky",
            ApprovalMode::Always => "always",
            ApprovalMode::Other => "other",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalPolicy {
    pub policy: ApprovalMode,
    /// With no phone registered, may the agent's own client, or a signed-in browser,
    /// approve? When this is false and an approval is needed, the launch is refused
    /// with `approval_required`.
    pub fallback: bool,
    pub phone_registered: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ScopeSummary {
    /// Entries in the workspace's scope now.
    pub current: u32,
    /// Entries the key's owner confirmed when the key was made.
    pub attested: u32,
    /// Entries in both: what a launch may target.
    pub effective: u32,
    pub effective_sha256: String,
}

/// `scope/list`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScopeList {
    pub entries: Vec<ScopeEntry>,
    /// The entries a launch may target, as the platform compares them.
    pub effective: Vec<String>,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScopeEntry {
    pub entry: String,
    #[serde(default)]
    pub note: Option<String>,
    /// A username, never an email address.
    #[serde(default)]
    pub added_by: Option<String>,
    #[serde(default)]
    pub added_on: Option<String>,
    /// Confirmed by the key's owner when the key was made.
    pub attested: bool,
}

/// How a target is to be read. Absent, the platform reads it by its form: a URL, a
/// range, or else a host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    Url,
    Host,
    Range,
    Zone,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeCheckRequest {
    /// At most [`MAX_CHECK_TARGETS`].
    pub targets: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<TargetKind>,
}

/// `scope/check`: one verdict per target, in the order given.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScopeCheck {
    pub results: Vec<ScopeVerdict>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScopeVerdict {
    pub target: String,
    /// Would a launch against it be admitted by the key's effective scope.
    pub admitted: bool,
    /// The entry that admits it.
    #[serde(default)]
    pub entry: Option<String>,
    /// Why not, in a few words, when it is not.
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodesRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub online_only: Option<bool>,
}

/// `nodes/list`. Addresses are never part of it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Nodes {
    pub nodes: Vec<Node>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Node {
    pub id: String,
    pub name: String,
    pub status: String,
    #[serde(default)]
    pub engines: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScansRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// At most [`MAX_LIST_LIMIT`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// `scans/list`: newest first. The key's own launches still waiting for approval are
/// rows too, with status `awaiting_approval`, no `id` and an `approval_id`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Scans {
    pub scans: Vec<ScanRow>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanRow {
    /// The workflow. `None` on a launch that is still waiting for approval.
    #[serde(default)]
    pub id: Option<String>,
    /// Set when the launch went through an approval.
    #[serde(default)]
    pub approval_id: Option<String>,
    /// Written by whoever started it, or derived from its target.
    pub name: String,
    /// A [`LaunchType`] name for a scan an agent could have started, the platform's own
    /// workflow type otherwise.
    #[serde(rename = "type")]
    pub kind: String,
    pub status: String,
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default)]
    pub findings_count: u64,
    pub created_at: String,
    /// `dashboard`, `mcp`, `valkyrie`, ... `None` on rows from before it was recorded.
    #[serde(default)]
    pub created_via: Option<String>,
    /// The cursor that continues the list after this row, so a client that keeps only
    /// part of a page can carry on from exactly where it stopped.
    #[serde(default)]
    pub cursor: Option<String>,
}

/// `scans/get`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanGet {
    pub scan: ScanRow,
    #[serde(default)]
    pub progress: Progress,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Progress {
    pub ops_expected: u64,
    pub ops_done: u64,
    #[serde(default)]
    pub probe_done: Option<u64>,
    #[serde(default)]
    pub probe_total: Option<u64>,
    #[serde(default)]
    pub phase: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultsRequest {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// At most [`MAX_RESULTS_LIMIT`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity_min: Option<String>,
}

/// `scans/results`: oldest first, paged on `(created_on, id)`, so the cursor of the last
/// page returns only what a running scan recorded since.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Results {
    pub results: Vec<ResultRow>,
    #[serde(default)]
    pub next_cursor: Option<String>,
    pub scan_status: String,
    /// Rows the plan's retention keeps out of this answer.
    #[serde(default)]
    pub hidden_by_retention: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResultRow {
    pub id: String,
    #[serde(default)]
    pub workflow_id: Option<String>,
    pub created_on: String,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub status_code: Option<u16>,
    /// What the engine recorded, at most [`MAX_ROW_BYTES`] of it.
    #[serde(default)]
    pub data: Value,
}

/// `results/get`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResultGet {
    pub result: ResultRow,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerdictsRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity_min: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// `verdicts/list`: newest `last_seen` first.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verdicts {
    pub verdicts: Vec<VerdictRow>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerdictRow {
    pub id: String,
    #[serde(default)]
    pub asset_id: Option<String>,
    #[serde(default)]
    pub asset_value: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub confidence: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub first_seen: Option<String>,
    #[serde(default)]
    pub last_seen: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerdictGetRequest {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_bytes: Option<u32>,
}

/// `verdicts/get`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerdictGet {
    pub verdict: VerdictDetail,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerdictDetail {
    #[serde(flatten)]
    pub row: VerdictRow,
    #[serde(default)]
    pub description: Option<String>,
    /// At most [`MAX_ROW_BYTES`].
    #[serde(default)]
    pub evidence: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetsRequest {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// `assets/list`: newest `last_seen` first.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Assets {
    pub assets: Vec<AssetRow>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssetRow {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub value: String,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub first_seen: Option<String>,
    #[serde(default)]
    pub last_seen: Option<String>,
    #[serde(default)]
    pub findings_count: u64,
}

/// `assets/get`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssetGet {
    pub asset: AssetDetail,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssetDetail {
    #[serde(flatten)]
    pub row: AssetRow,
    /// What the engines recorded about it.
    #[serde(default)]
    pub attributes: Value,
    #[serde(default)]
    pub parent_id: Option<String>,
    #[serde(default)]
    pub children_count: u64,
    #[serde(default)]
    pub recent_verdicts: Vec<VerdictRow>,
}

// ---------------------------------------------------------------------------
// Launching

/// What an agent may start. The platform chooses everything not in [`StartOptions`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchType {
    /// Subdomain enumeration under one apex domain.
    Recon,
    PortScan,
    /// One URL, pinned to its host.
    Crawl,
    ContentDiscovery,
    VulnScan,
    AuthzScan,
}

impl LaunchType {
    pub const ALL: [LaunchType; 6] = [
        LaunchType::Recon,
        LaunchType::PortScan,
        LaunchType::Crawl,
        LaunchType::ContentDiscovery,
        LaunchType::VulnScan,
        LaunchType::AuthzScan,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            LaunchType::Recon => "recon",
            LaunchType::PortScan => "port_scan",
            LaunchType::Crawl => "crawl",
            LaunchType::ContentDiscovery => "content_discovery",
            LaunchType::VulnScan => "vuln_scan",
            LaunchType::AuthzScan => "authz_scan",
        }
    }

    pub fn parse(s: &str) -> Option<LaunchType> {
        LaunchType::ALL.into_iter().find(|t| t.as_str() == s)
    }

    /// How many targets one launch takes.
    pub fn targets_allowed(self) -> std::ops::RangeInclusive<usize> {
        match self {
            LaunchType::PortScan | LaunchType::VulnScan => 1..=20,
            _ => 1..=1,
        }
    }

    /// How a target of this type is read against a scope.
    pub fn target_kind(self) -> TargetKind {
        match self {
            LaunchType::Recon => TargetKind::Zone,
            LaunchType::PortScan => TargetKind::Host,
            _ => TargetKind::Url,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconMode {
    /// Sources that never contact the domain.
    Passive,
    /// Also resolves and probes names under it.
    Active,
}

/// The options an agent may set, per type. Anything else is fixed by the platform.
/// Each field belongs to one type; [`StartOptions::check`] refuses one set for another.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartOptions {
    /// recon. Default `passive`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<ReconMode>,
    /// port_scan: `top-100`, `top-1000` (the default), `common-web`, or a list such as
    /// `22,80,8000-8100` of at most [`MAX_PORTS`] ports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ports: Option<String>,
    /// crawl: 1 to 10, default 3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_depth: Option<u32>,
    /// crawl: 1 to 2,000, default 500.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_pages: Option<u32>,
    /// content_discovery: a wordlist name, default `common`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wordlist: Option<String>,
    /// content_discovery: at most 10.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Vec<String>>,
    /// content_discovery. Default false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recurse: Option<bool>,
    /// vuln_scan: `info` to `critical`, default `medium`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity_min: Option<String>,
    /// vuln_scan: at most 20.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    /// authz_scan: role names, at least one. `anonymous` is always added.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identities: Option<Vec<String>>,
}

/// Ports one `port_scan` list may name.
pub const MAX_PORTS: u32 = 2000;
pub const PORT_PRESETS: [&str; 3] = ["top-100", "top-1000", "common-web"];
pub const SEVERITIES: [&str; 5] = ["info", "low", "medium", "high", "critical"];

/// How many ports a `ports` value names, or why it is not one.
pub fn count_ports(spec: &str) -> Result<u32, String> {
    let s = spec.trim();
    if PORT_PRESETS.contains(&s) {
        return Ok(0);
    }
    let mut n: u32 = 0;
    for part in s.split(',') {
        let part = part.trim();
        let port = |p: &str| -> Result<u16, String> {
            match p.trim().parse::<u16>() {
                Ok(v) if v > 0 => Ok(v),
                _ => Err(format!("{p:?} is not a port")),
            }
        };
        let width = match part.split_once('-') {
            Some((a, b)) => {
                let (a, b) = (port(a)?, port(b)?);
                if a > b {
                    return Err(format!("{part:?} runs backwards"));
                }
                u32::from(b - a) + 1
            }
            None => {
                port(part)?;
                1
            }
        };
        n = n.saturating_add(width);
        if n > MAX_PORTS {
            return Err(format!("more than {MAX_PORTS} ports"));
        }
    }
    Ok(n)
}

impl StartOptions {
    /// Is every option set one this type takes, in its range.
    pub fn check(&self, kind: LaunchType) -> Result<(), String> {
        let set: [(&str, bool, LaunchType); 10] = [
            ("mode", self.mode.is_some(), LaunchType::Recon),
            ("ports", self.ports.is_some(), LaunchType::PortScan),
            ("max_depth", self.max_depth.is_some(), LaunchType::Crawl),
            ("max_pages", self.max_pages.is_some(), LaunchType::Crawl),
            (
                "wordlist",
                self.wordlist.is_some(),
                LaunchType::ContentDiscovery,
            ),
            (
                "extensions",
                self.extensions.is_some(),
                LaunchType::ContentDiscovery,
            ),
            (
                "recurse",
                self.recurse.is_some(),
                LaunchType::ContentDiscovery,
            ),
            (
                "severity_min",
                self.severity_min.is_some(),
                LaunchType::VulnScan,
            ),
            ("tags", self.tags.is_some(), LaunchType::VulnScan),
            (
                "identities",
                self.identities.is_some(),
                LaunchType::AuthzScan,
            ),
        ];
        for (name, given, owner) in set {
            if given && owner != kind {
                return Err(format!(
                    "{name} is an option of {}, not {}",
                    owner.as_str(),
                    kind.as_str()
                ));
            }
        }
        if let Some(p) = &self.ports {
            count_ports(p)?;
        }
        if let Some(d) = self.max_depth
            && !(1..=10).contains(&d)
        {
            return Err("max_depth must be between 1 and 10".into());
        }
        if let Some(p) = self.max_pages
            && !(1..=2000).contains(&p)
        {
            return Err("max_pages must be between 1 and 2000".into());
        }
        if let Some(w) = &self.wordlist
            && (w.is_empty() || w.len() > 64)
        {
            return Err("wordlist must be a name of 1 to 64 characters".into());
        }
        if self.extensions.as_ref().is_some_and(|e| e.len() > 10) {
            return Err("at most 10 extensions".into());
        }
        if let Some(s) = &self.severity_min
            && !SEVERITIES.contains(&s.as_str())
        {
            return Err(format!(
                "severity_min must be one of {}",
                SEVERITIES.join(", ")
            ));
        }
        if self.tags.as_ref().is_some_and(|t| t.len() > 20) {
            return Err("at most 20 tags".into());
        }
        if let Some(ids) = &self.identities
            && (ids.is_empty() || ids.len() > 20)
        {
            return Err("identities must name between 1 and 20 roles".into());
        }
        Ok(())
    }
}

/// `scans/start`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartRequest {
    #[serde(rename = "type")]
    pub kind: LaunchType,
    pub targets: Vec<String>,
    /// Empty: every online node in the workspace with the engine for this type.
    #[serde(default)]
    pub node_ids: Vec<String>,
    #[serde(default)]
    pub options: StartOptions,
    /// The client's id for this launch. A second `scans/start` with the same key and
    /// `request_id` within 10 minutes answers with what the first one produced, so a
    /// retry after a lost answer does not start a second scan.
    pub request_id: String,
    /// Set when the client asked nobody before sending, because `whoami` said the
    /// workspace holds every launch for a person. The platform then holds this launch
    /// for a person whatever its policy is by now: it answers 202, or refuses with
    /// `approval_required` when nobody can approve it, and never 201. Omitted when
    /// false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub hold_for_approval: bool,
}

/// `scans/start`, 201: the scan was created and started.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Started {
    pub scan: ScanRow,
}

/// `scans/start`, 202: the launch waits for a person. Nothing has been created except
/// the approval, and the platform launches the request exactly as it stored it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AwaitingApproval {
    pub approval: Approval,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Expired,
    /// Withdrawn by the agent through `scans/cancel`.
    Cancelled,
    #[serde(other)]
    Other,
}

impl ApprovalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ApprovalStatus::Pending => "pending",
            ApprovalStatus::Approved => "approved",
            ApprovalStatus::Denied => "denied",
            ApprovalStatus::Expired => "expired",
            ApprovalStatus::Cancelled => "cancelled",
            ApprovalStatus::Other => "other",
        }
    }
}

/// After an approval, the platform's own launch of the stored request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchState {
    Launching,
    Launched,
    Failed,
    #[serde(other)]
    Other,
}

/// Who decided an approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecidedVia {
    /// A signed approval from the owner's registered phone.
    Phone,
    /// The owner, signed in to the dashboard.
    Dashboard,
    /// The agent's own client, asking the person through a form.
    AgentClient,
    #[serde(other)]
    Other,
}

impl DecidedVia {
    pub fn as_str(self) -> &'static str {
        match self {
            DecidedVia::Phone => "phone",
            DecidedVia::Dashboard => "dashboard",
            DecidedVia::AgentClient => "agent_client",
            DecidedVia::Other => "other",
        }
    }
}

/// A phone that can approve, as the person named it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Device {
    pub name: String,
    #[serde(default)]
    pub last_seen_at: Option<String>,
}

/// What an approval would launch, as the platform stored it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalAction {
    #[serde(rename = "type")]
    pub kind: LaunchType,
    pub targets: Vec<String>,
    /// How many nodes it would run on.
    pub nodes: u32,
    #[serde(default)]
    pub options: StartOptions,
}

/// An approval, as `scans/start` (202) and the `approvals/*` routes return it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Approval {
    pub id: String,
    pub status: ApprovalStatus,
    pub expires_at: String,
    /// The owner's registered phones. When there is one, only a phone can approve; the
    /// dashboard and the agent's client can only deny.
    #[serde(default)]
    pub devices: Vec<Device>,
    /// With no phone registered: may the agent's client or a signed-in browser approve.
    #[serde(default)]
    pub fallback: bool,
    /// The page where the owner can see the request and decide it.
    pub approve_url: String,
    #[serde(default)]
    pub action: Option<ApprovalAction>,
    #[serde(default)]
    pub launch_state: Option<LaunchState>,
    #[serde(default)]
    pub decided_via: Option<DecidedVia>,
    #[serde(default)]
    pub decided_at: Option<String>,
    /// The workflow, once launched.
    #[serde(default)]
    pub workflow_id: Option<String>,
    #[serde(default)]
    pub launch_error: Option<LaunchError>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LaunchError {
    pub reason: Reason,
    #[serde(default)]
    pub message: String,
}

/// `approvals/get`, `approvals/wait` and `approvals/decide`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalAnswer {
    pub approval: Approval,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WaitRequest {
    pub id: String,
    /// At most [`MAX_WAIT_SECONDS`]. The answer comes as soon as the approval changes.
    pub wait_seconds: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Approve,
    Deny,
}

/// The only way an MCP key decides: the person answered in the agent's client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Via {
    AgentClient,
}

/// `approvals/decide`. A deny is always accepted from the key's owner. An approve is
/// accepted only when the approval says `fallback`, and is refused with
/// `elicitation_not_allowed` when a phone is registered.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecideRequest {
    pub id: String,
    pub decision: Decision,
    pub via: Via,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancelKind {
    #[default]
    Scan,
    Approval,
}

/// `scans/cancel`. A scan is stopped only when the key's owner started it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelRequest {
    pub id: String,
    #[serde(default)]
    pub kind: CancelKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancelResult {
    /// A running scan was told to stop.
    Stopped,
    /// The scan had already ended.
    NotRunning,
    /// A pending approval was withdrawn.
    Cancelled,
    #[serde(other)]
    Other,
}

impl CancelResult {
    pub fn as_str(self) -> &'static str {
        match self {
            CancelResult::Stopped => "stopped",
            CancelResult::NotRunning => "not_running",
            CancelResult::Cancelled => "cancelled",
            CancelResult::Other => "other",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Cancelled {
    pub result: CancelResult,
    /// The scan's or the approval's status afterwards.
    #[serde(default)]
    pub status: Option<String>,
}

/// `key/revoke`: the presenting key is revoked, and every later call with it is
/// `key_revoked`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Revoked {
    pub revoked: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn every_reason_reads_back_as_itself() {
        for r in Reason::ALL {
            assert_eq!(Reason::parse(r.as_str()), r);
            let v = serde_json::to_value(r).unwrap();
            assert_eq!(v, json!(r.as_str()));
            assert_eq!(serde_json::from_value::<Reason>(v).unwrap(), r);
        }
        assert_eq!(Reason::parse("something_new"), Reason::Other);
        let r: Reason = serde_json::from_value(json!("something_new")).unwrap();
        assert_eq!(r, Reason::Other);
    }

    #[test]
    fn only_the_three_key_codes_reject_the_key() {
        let rejecting: Vec<Reason> = Reason::ALL
            .into_iter()
            .filter(|r| r.rejects_key())
            .collect();
        assert_eq!(
            rejecting,
            [Reason::KeyInvalid, Reason::KeyRevoked, Reason::KeyExpired]
        );
    }

    #[test]
    fn keys_are_cfm_and_32_lowercase_hex() {
        let k = "cfm_0123456789abcdef0123456789abcdef";
        assert!(valid_key(k));
        assert_eq!(key_prefix(k).as_deref(), Some("cfm_01234567"));
        for bad in [
            "cfk_0123456789abcdef0123456789abcdef",
            "cfm_0123456789ABCDEF0123456789abcdef",
            "cfm_0123456789abcdef0123456789abcde",
            "cfm_0123456789abcdef0123456789abcdef0",
            " cfm_0123456789abcdef0123456789abcdef",
            "",
        ] {
            assert!(!valid_key(bad), "{bad:?}");
            assert_eq!(key_prefix(bad), None);
        }
    }

    #[test]
    fn ids_go_round_and_refuse_anything_else() {
        let uuid = "6f1c0e2a-1b2c-4d3e-8f90-0123456789ab";
        for kind in IdKind::ALL {
            let id = encode(kind, uuid).unwrap();
            assert!(id.starts_with(kind.prefix()));
            assert_eq!(id.len(), 35);
            assert_eq!(decode(&id), Some((kind, uuid.to_string())));
        }
        assert_eq!(
            encode(IdKind::Scan, "6F1C0E2A-1B2C-4D3E-8F90-0123456789AB").as_deref(),
            Some("cs_6f1c0e2a1b2c4d3e8f900123456789ab")
        );
        for bad in [
            "s_0123456789",
            "cs_6f1c0e2a1b2c4d3e8f900123456789a",
            "cs_6F1C0E2A1B2C4D3E8F900123456789AB",
            "cx_6f1c0e2a1b2c4d3e8f900123456789ab",
            "cs_../../../etc/passwd/0123456789ab",
            "cs_6f1c0e2a1b2c4d3e8f900123456789ab ",
        ] {
            assert_eq!(decode(bad), None, "{bad:?}");
        }
        assert_eq!(encode(IdKind::Scan, "not-a-uuid"), None);
        assert_eq!(
            encode(IdKind::Scan, "6f1c0e2a1b2c4d3e8f900123456789ab"),
            None
        );
    }

    #[test]
    fn a_refusal_reads_as_the_platform_writes_it() {
        let wire = json!({"status": 403, "message": "Out of scope",
            "errors": ["api.other.example:443 is not in the scope the key's owner confirmed. Nothing was started."],
            "data": {"reason": "out_of_scope", "refused": [{"target": "https://api.other.example/", "host": "api.other.example", "port": 443}]}});
        let e: Envelope<Refusal> = serde_json::from_value(wire).unwrap();
        assert_eq!(e.status, 403);
        assert_eq!(e.data.reason, Reason::OutOfScope);
        assert_eq!(e.data.refused[0].port, Some(443));
    }

    #[test]
    fn a_pending_approval_reads_as_the_platform_writes_it() {
        let wire = json!({"status": 202, "message": "Waiting for approval", "errors": [],
          "data": {"approval": {
            "id": "6f1c0e2a-1b2c-4d3e-8f90-0123456789ab", "status": "pending",
            "expires_at": "2026-11-02T10:24:00Z",
            "devices": [{"name": "Pixel 8", "last_seen_at": "2026-11-02T10:13:51Z"}],
            "fallback": false,
            "approve_url": "https://crossfyre.io/m/approve/6f1c0e2a-1b2c-4d3e-8f90-0123456789ab",
            "action": {"type": "vuln_scan", "targets": ["https://app.example.com/"], "nodes": 2,
                       "options": {"severity_min": "medium"}}}}});
        let e: Envelope<AwaitingApproval> = serde_json::from_value(wire).unwrap();
        let a = e.data.approval;
        assert_eq!(a.status, ApprovalStatus::Pending);
        assert_eq!(a.devices[0].name, "Pixel 8");
        assert_eq!(a.action.unwrap().kind, LaunchType::VulnScan);
        assert!(a.launch_state.is_none());
    }

    #[test]
    fn unknown_states_from_a_newer_platform_do_not_break_a_read() {
        let a: Approval = serde_json::from_value(json!({
            "id": "6f1c0e2a-1b2c-4d3e-8f90-0123456789ab", "status": "escalated",
            "expires_at": "2026-11-02T10:24:00Z", "approve_url": "https://crossfyre.io/m/approve/x",
            "launch_state": "queued", "decided_via": "watch"}))
        .unwrap();
        assert_eq!(a.status, ApprovalStatus::Other);
        assert_eq!(a.launch_state, Some(LaunchState::Other));
        assert_eq!(a.decided_via, Some(DecidedVia::Other));
    }

    #[test]
    fn options_belong_to_one_type() {
        let o = StartOptions {
            max_depth: Some(3),
            ..Default::default()
        };
        assert!(o.check(LaunchType::Crawl).is_ok());
        assert!(o.check(LaunchType::VulnScan).is_err());
        let o = StartOptions {
            max_depth: Some(11),
            ..Default::default()
        };
        assert!(o.check(LaunchType::Crawl).is_err());
        let o = StartOptions {
            identities: Some(vec![]),
            ..Default::default()
        };
        assert!(o.check(LaunchType::AuthzScan).is_err());
        let bad: Result<StartOptions, _> = serde_json::from_value(json!({"follow_external": true}));
        assert!(
            bad.is_err(),
            "an option no type has is refused, not ignored"
        );
    }

    #[test]
    fn port_lists_are_counted_and_capped() {
        assert_eq!(count_ports("top-1000"), Ok(0));
        assert_eq!(count_ports("22,80,8000-8100"), Ok(103));
        assert!(count_ports("1-2001").is_err());
        assert!(count_ports("0").is_err());
        assert!(count_ports("90-80").is_err());
        assert!(count_ports("http").is_err());
        assert!(count_ports("1-65535,1-65535").is_err());
    }

    #[test]
    fn the_vocabulary_is_made_of_words() {
        let lists: [&[&str]; 7] = [
            &vocab::SCAN_STATUSES,
            &vocab::SCAN_ENDED,
            &vocab::VERDICT_STATUSES,
            &vocab::ASSET_STATUSES,
            &vocab::NODE_STATUSES,
            &vocab::CONFIDENCES,
            &vocab::CHANNELS,
        ];
        for w in lists.into_iter().flatten() {
            assert!(vocab::is_word(w), "{w}");
        }
        for e in vocab::SCAN_ENDED {
            assert!(vocab::SCAN_STATUSES.contains(&e), "{e}");
        }
        for t in LaunchType::ALL {
            assert!(vocab::is_word(t.as_str()));
        }
        for bad in [
            "",
            "Running",
            "ignore previous instructions",
            "-x",
            "a\u{200B}b",
            &"a".repeat(65),
        ] {
            assert!(!vocab::is_word(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_start_request_takes_nothing_it_does_not_name() {
        let ok: StartRequest = serde_json::from_value(json!({
            "type": "crawl", "targets": ["https://app.example.com/"],
            "options": {"max_depth": 2}, "request_id": "r_1"}))
        .unwrap();
        assert_eq!(ok.kind, LaunchType::Crawl);
        assert!(ok.node_ids.is_empty());
        assert!(!ok.hold_for_approval);
        // Sent only when set, so a platform that predates it reads every other launch.
        let back = serde_json::to_value(&ok).unwrap();
        assert!(back.get("hold_for_approval").is_none(), "{back}");
        let held = StartRequest {
            hold_for_approval: true,
            ..ok
        };
        assert_eq!(
            serde_json::to_value(&held).unwrap()["hold_for_approval"],
            true
        );
        let bad: Result<StartRequest, _> = serde_json::from_value(json!({
            "type": "crawl", "targets": [], "request_id": "r_1", "workspace_id": "x"}));
        assert!(bad.is_err());
    }
}

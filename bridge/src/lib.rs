//! The messages `crossfyre mcp` and a running Workbench exchange, protocol version 1.
//!
//! A Workbench with Agent access on listens on a Unix socket in its data directory and
//! writes an [`Endpoint`] file saying where. `crossfyre mcp` reads that file, connects,
//! and from then on the two speak the shapes in this crate. Both ends depend on it, so a
//! field renamed on one side fails to compile on the other instead of arriving as a
//! silent `null`.
//!
//! Nothing here does I/O. It holds the shapes, the limits both ends enforce, and the
//! parsing that has to agree on both sides.
//!
//! # Framing
//!
//! Newline-delimited JSON, UTF-8, one object per line. A request line is at most
//! [`MAX_REQUEST_LINE`] bytes and a server line at most [`MAX_RESPONSE_LINE`].
//!
//! 1. The client's first line is [`Handshake::Hello`], carrying the endpoint's token.
//! 2. The server answers [`Handshake::Welcome`], or [`Handshake::Refused`] and closes.
//! 3. The client sends [`Request`]s. The server sends a [`Response`] for each, and
//!    [`Event`]s whenever something changes, in any order.
//!
//! # Compatibility
//!
//! Fields can be added without a version bump, so nothing here refuses a field it does
//! not know. A new method is advertised in [`Welcome::capabilities`] and a client uses it
//! only when it is there. Error codes, refusal codes and origins a client does not know
//! are kept as sent rather than failing the whole line.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json::value::RawValue;

mod edits;
mod handle;
mod methods;

pub use edits::{EDIT_ENTRIES_MAX, EDIT_VALUE_MAX, Edits, Pairs};
pub use handle::{
    CURSOR_PREFIX, Cursor, ExchangeHandle, HANDLE_PREFIX, ProjectTag, SITE_MAP_CURSOR_HOST_MAX,
    SITE_MAP_CURSOR_METHOD_MAX, SITE_MAP_CURSOR_PATH_MAX, is_project_uid,
};
pub use methods::*;

/// The protocol this crate speaks.
pub const PROTOCOL: u32 = 1;

/// The `v` of an [`Endpoint`] file this crate reads.
pub const ENDPOINT_VERSION: u32 = 1;

/// The `app` an [`Endpoint`] file names.
pub const ENDPOINT_APP: &str = "crossfyre-workbench";

/// The longest line a client may send.
pub const MAX_REQUEST_LINE: usize = 64 * 1024;

/// The longest line a server may send. The per-method caps are sized to keep a result
/// under it.
pub const MAX_RESPONSE_LINE: usize = 1024 * 1024;

/// An endpoint file larger than this is not read at all.
pub const MAX_ENDPOINT_FILE: usize = 4096;

/// A string enum whose values a newer peer may add to. An unknown value is kept as
/// `Other` with its text, so one new code does not make every line that carries it
/// unreadable.
macro_rules! open_enum {
    ($(#[$m:meta])* $name:ident { $($(#[$vm:meta])* $var:ident = $s:literal,)* }) => {
        $(#[$m])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub enum $name {
            $($(#[$vm])* $var,)*
            /// A value this version does not know, kept as it was sent.
            Other(String),
        }

        impl $name {
            pub fn as_str(&self) -> &str {
                match self {
                    $(Self::$var => $s,)*
                    Self::Other(s) => s,
                }
            }

            pub fn parse(s: &str) -> Self {
                match s {
                    $($s => Self::$var,)*
                    other => Self::Other(other.to_string()),
                }
            }
        }

        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                String::deserialize(d).map(|s| Self::parse(&s))
            }
        }
    };
}
pub(crate) use open_enum;

/// Is this a token as an endpoint file carries one: 64 lowercase hex characters.
pub fn is_token(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// For an `Option` whose `null` means something, such as "no project is open": the
/// field has to be there. Without this serde reads a missing field as `None`, and a
/// line that left it out would say the project closed.
fn required<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d)
}

/// One line of JSON, ending in a newline. Compact JSON escapes every newline inside a
/// string, so the only one in the output is the last.
pub fn to_line<T: Serialize>(msg: &T) -> String {
    let mut s = serde_json::to_string(msg).unwrap_or_default();
    s.push('\n');
    s
}

// ---------------------------------------------------------------------------
// The endpoint file
// ---------------------------------------------------------------------------

/// `<data dir>/control/<pid>.json`, written by a Workbench while it runs.
///
/// With Agent access off the file is still written, with no socket and no token, so a
/// client can say "a Workbench is running with Agent access off" rather than "no
/// Workbench".
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub v: u32,
    pub app: String,
    pub app_version: String,
    pub pid: u32,
    pub started_ms: i64,
    pub protocol: u32,
    pub agent_access: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Why there is no socket although access is on, when the bridge could not start.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

impl Endpoint {
    /// Read an endpoint file's contents, refusing one a client must not act on.
    ///
    /// The ownership, mode and directory checks need the file itself and are the
    /// client's. This is the part that only needs the bytes.
    pub fn parse(bytes: &[u8]) -> Result<Endpoint, String> {
        if bytes.len() > MAX_ENDPOINT_FILE {
            return Err(format!("larger than {MAX_ENDPOINT_FILE} bytes"));
        }
        let e: Endpoint = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if e.v != ENDPOINT_VERSION {
            return Err(format!("version {} is not {ENDPOINT_VERSION}", e.v));
        }
        match (e.agent_access, &e.socket, &e.token) {
            (true, Some(socket), Some(token)) => {
                if socket.is_empty() {
                    return Err("the socket path is empty".into());
                }
                if !is_token(token) {
                    return Err("the token is not 64 lowercase hex characters".into());
                }
            }
            // Access on with the bridge failed to start: the file says why.
            (true, None, None) if e.why.is_some() => {}
            (true, _, _) => {
                return Err("agent access is on but there is no socket and token".into());
            }
            (false, None, None) => {}
            (false, _, _) => {
                return Err("agent access is off but a socket or token is present".into());
            }
        }
        Ok(e)
    }

    /// Can a client connect: access on, and a socket and token present.
    pub fn connectable(&self) -> Option<(&str, &str)> {
        match (self.agent_access, &self.socket, &self.token) {
            (true, Some(s), Some(t)) => Some((s, t)),
            _ => None,
        }
    }
}

impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Endpoint")
            .field("v", &self.v)
            .field("app", &self.app)
            .field("app_version", &self.app_version)
            .field("pid", &self.pid)
            .field("started_ms", &self.started_ms)
            .field("protocol", &self.protocol)
            .field("agent_access", &self.agent_access)
            .field("socket", &self.socket)
            .field("token", &self.token.as_ref().map(|_| "[redacted]"))
            .field("why", &self.why)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// The handshake
// ---------------------------------------------------------------------------

/// The first line each way.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Handshake {
    Hello(Hello),
    Welcome(Welcome),
    Refused(Refused),
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub protocol: u32,
    pub token: String,
    pub client: ClientInfo,
}

impl std::fmt::Debug for Hello {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hello")
            .field("protocol", &self.protocol)
            .field("token", &"[redacted]")
            .field("client", &self.client)
            .finish()
    }
}

/// Who is connecting. `label` is what the MCP client said it was, which nobody checked,
/// and is shown as that.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientInfo {
    pub name: String,
    pub version: String,
    pub pid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Welcome {
    pub protocol: u32,
    pub app_version: String,
    pub pid: u32,
    /// The methods this server answers, by [`Method::as_str`].
    pub capabilities: Vec<String>,
    #[serde(deserialize_with = "required")]
    pub project: Option<ProjectInfo>,
}

impl Welcome {
    pub fn supports(&self, m: Method) -> bool {
        self.capabilities.iter().any(|c| c == m.as_str())
    }
}

/// The open project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectInfo {
    /// 32 lowercase hex characters, made once per project. See [`is_project_uid`].
    pub uid: String,
    pub name: String,
    pub exchanges: u64,
}

/// A project named in an error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectRef {
    pub uid: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refused {
    pub code: RefusedCode,
    /// The protocols the server speaks, with [`RefusedCode::Protocol`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported: Vec<u32>,
}

open_enum! {
    /// Why a connection was refused at the handshake.
    RefusedCode {
        /// The client's protocol is not one the server speaks.
        Protocol = "protocol",
        /// The token did not match.
        Token = "token",
        /// The server already has as many connections as it takes.
        Busy = "busy",
    }
}

// ---------------------------------------------------------------------------
// Requests, responses and events
// ---------------------------------------------------------------------------

/// One request as a server reads it. [`Call::from_request`] gives it a type, and
/// [`Call::to_line`] writes one.
///
/// The method is a string here rather than [`Method`] so a server can still answer a
/// method it does not know, by id, with `unsupported_method`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub id: u64,
    pub method: String,
    /// As written on the line, so the typed params see names in their order and see a
    /// name written twice.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Box<RawValue>>,
}

impl Request {
    pub fn parse(line: &str) -> Result<Request, String> {
        if line.len() > MAX_REQUEST_LINE {
            return Err(format!(
                "a request line is at most {MAX_REQUEST_LINE} bytes"
            ));
        }
        serde_json::from_str(line).map_err(|e| e.to_string())
    }
}

/// The answer to one request.
///
/// A server builds it with the method's result type, so the line keeps that type's field
/// order. A client reads it with the default, a JSON value, because it has to see the id
/// before it knows which method the answer is for, and then calls
/// [`Response::into_result`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Response<T = Value> {
    pub id: u64,
    #[serde(flatten)]
    pub outcome: Outcome<T>,
}

/// `{"ok": ...}` or `{"err": ...}` beside the id.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome<T = Value> {
    Ok(T),
    Err(ErrorBody),
}

impl<T> Response<T> {
    pub fn ok(id: u64, result: T) -> Response<T> {
        Response {
            id,
            outcome: Outcome::Ok(result),
        }
    }

    pub fn err(id: u64, e: ErrorBody) -> Response<T> {
        Response {
            id,
            outcome: Outcome::Err(e),
        }
    }
}

impl Response {
    /// The result as the type the caller asked for. A result that does not have that
    /// shape is an `internal` error, since the method was the caller's own choice.
    pub fn into_result<T: serde::de::DeserializeOwned>(self) -> Result<T, ErrorBody> {
        match self.outcome {
            Outcome::Ok(v) => serde_json::from_value(v).map_err(|e| {
                ErrorBody::new(ErrorCode::Internal, format!("unexpected result: {e}"))
            }),
            Outcome::Err(e) => Err(e),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: ErrorCode,
    pub message: String,
    /// With `project_changed`: the project that is open now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<ProjectRef>,
}

impl ErrorBody {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> ErrorBody {
        ErrorBody {
            code,
            message: message.into(),
            current: None,
        }
    }
}

open_enum! {
    ErrorCode {
        /// No project is open.
        NoProject = "no_project",
        /// The request named a project that is no longer the open one.
        ProjectChanged = "project_changed",
        NotFound = "not_found",
        /// The project's scope refused it. The message is the scope's refusal text.
        OutOfScope = "out_of_scope",
        /// None of the pinned addresses is one the server's own lookup gave for the host.
        PinMismatch = "pin_mismatch",
        BinaryBody = "binary_body",
        TooLarge = "too_large",
        InvalidParams = "invalid_params",
        /// Too many requests in flight or in the last second.
        Busy = "busy",
        UnsupportedMethod = "unsupported_method",
        SendFailed = "send_failed",
        /// Agent access was turned off.
        AccessOff = "access_off",
        Internal = "internal",
    }
}

/// Something changed in the Workbench. Sent unasked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// A project was opened, or closed (`None`).
    Project {
        #[serde(deserialize_with = "required")]
        project: Option<ProjectInfo>,
    },
    /// The operator selected something else.
    Selection { changed_ms: i64 },
    /// The project's scope was changed.
    Scope { restricted: bool, rules: u64 },
    /// Agent access was turned on or off. Off is followed by the connection closing.
    AgentAccess { enabled: bool },
}

impl Event {
    /// The `event` values this version knows.
    pub const NAMES: [&'static str; 4] = ["project", "selection", "scope", "agent_access"];
}

/// One line from the server, after the handshake.
#[derive(Debug, Clone, PartialEq)]
pub enum ServerLine {
    Response(Response),
    Event(Event),
    /// An event this version does not know, by name. Ignoring it is correct: a newer
    /// server adds events without a version bump.
    UnknownEvent(String),
}

impl ServerLine {
    pub fn parse(line: &str) -> Result<ServerLine, String> {
        if line.len() > MAX_RESPONSE_LINE {
            return Err(format!(
                "a server line is at most {MAX_RESPONSE_LINE} bytes"
            ));
        }
        let v: Value = serde_json::from_str(line).map_err(|e| e.to_string())?;
        if let Some(name) = v.get("event").and_then(Value::as_str) {
            if !Event::NAMES.contains(&name) {
                return Ok(ServerLine::UnknownEvent(name.to_string()));
            }
            return serde_json::from_value(v)
                .map(ServerLine::Event)
                .map_err(|e| e.to_string());
        }
        serde_json::from_value(v)
            .map(ServerLine::Response)
            .map_err(|e| e.to_string())
    }
}

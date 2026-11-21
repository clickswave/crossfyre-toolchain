//! `test_injection`: plessor's `inject` operation, run as a scan with a handle (see
//! `engine_scan`).

use super::engine_scan::{Plan, Run, start_scan};
use super::overrides::{self, Asked, Via};
use super::{in_range, parse_args};
use crate::confirm::{AskKind, WriteAsk};
use crate::core::{CallNote, Done, Intent, Mcp, Refusal, TrafficRequest};
use crate::guard::{self, Dest};
use crate::peer::ClientPeer;
use crate::untrusted;
use cfx_scope::Point;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

/// The classes this server lets a model name. plessor's opt-in classes (race,
/// smuggling, prototype pollution, tampering) each need a confirmation of their own
/// and are not offered yet.
pub(crate) const CLASSES: [&str; 15] = [
    "sqli",
    "xss",
    "cmdi",
    "lfi",
    "ssti",
    "ssrf",
    "nosql",
    "xxe",
    "crlf",
    "open_redirect",
    "deserialization",
    "cors",
    "exposure",
    "inventory",
    "ratelimit",
];

const METHODS: [&str; 5] = ["GET", "POST", "PUT", "PATCH", "DELETE"];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    endpoints: Option<Vec<EndpointArg>>,
    #[serde(default)]
    classes: Option<Vec<String>>,
    #[serde(default)]
    test_writes: bool,
    #[serde(default)]
    wait_seconds: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointArg {
    url: String,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    params: Option<Vec<String>>,
    #[serde(default)]
    body: Option<Vec<BodyArg>>,
    #[serde(default)]
    body_type: Option<String>,
}

/// Serialised into the operation as plessor reads a body field, where a missing value
/// is an empty string and a null fails the whole operation.
#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct BodyArg {
    name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    ty: Option<String>,
}

struct Endpoint {
    dest: Dest,
    op: Value,
}

fn endpoints(a: &Args) -> Result<Vec<Endpoint>, Refusal> {
    let list: Vec<EndpointArg> = match (&a.url, &a.endpoints) {
        (Some(u), None) => vec![EndpointArg {
            url: u.clone(),
            method: None,
            params: None,
            body: None,
            body_type: None,
        }],
        (None, Some(eps)) => {
            if eps.is_empty() || eps.len() > 100 {
                return Err(Refusal::invalid(
                    "endpoints must hold between 1 and 100 entries",
                ));
            }
            eps.iter()
                .map(|e| EndpointArg {
                    url: e.url.clone(),
                    method: e.method.clone(),
                    params: e.params.clone(),
                    body: e.body.as_ref().map(|b| {
                        b.iter()
                            .map(|f| BodyArg {
                                name: f.name.clone(),
                                value: f.value.clone(),
                                ty: f.ty.clone(),
                            })
                            .collect()
                    }),
                    body_type: e.body_type.clone(),
                })
                .collect()
        }
        _ => {
            return Err(Refusal::invalid(
                "give exactly one of url (one URL with the query parameters to test) or \
                 endpoints",
            ));
        }
    };
    let mut out = Vec::new();
    for e in list {
        let dest = guard::parse_target(&e.url)
            .map_err(|err| Refusal::invalid(format!("endpoint url: {err}")))?;
        let method = e
            .method
            .unwrap_or_else(|| "GET".into())
            .to_ascii_uppercase();
        if !METHODS.contains(&method.as_str()) {
            return Err(Refusal::invalid(
                "method must be one of GET, POST, PUT, PATCH, DELETE",
            ));
        }
        let params = e.params.unwrap_or_default();
        if params.len() > 50 || params.iter().any(|p| p.len() > 200) {
            return Err(Refusal::invalid(
                "params holds at most 50 names of at most 200 characters",
            ));
        }
        let body = e.body.unwrap_or_default();
        if body.len() > 50
            || body
                .iter()
                .any(|f| f.name.len() > 200 || f.value.as_ref().is_some_and(|v| v.len() > 8192))
        {
            return Err(Refusal::invalid(
                "body holds at most 50 fields, each name at most 200 characters and each \
                 value at most 8 KB",
            ));
        }
        let body_type = e.body_type.unwrap_or_else(|| "form".into());
        if body_type != "form" && body_type != "json" {
            return Err(Refusal::invalid("body_type must be form or json"));
        }
        // plessor sends the other fields as given with every test, so an endpoint that
        // asks the target for DELETE by override is a DELETE endpoint to it.
        if !a.test_writes {
            let from_query = overrides::in_query(&dest.url)
                .into_iter()
                .map(|(_, v)| Asked::new(Via::Query, Some(&v)));
            let from_body = body
                .iter()
                .filter(|f| overrides::is_field(&f.name))
                .map(|f| Asked::new(Via::Field, Some(f.value.as_deref().unwrap_or(""))));
            if let Some(asked) = from_query.chain(from_body).find(Asked::beyond_post) {
                return Err(Refusal::invalid(format!(
                    "an endpoint is a {}, which can change or destroy data; it is tested only \
                     with test_writes, which needs allow_writes in the scope file and a \
                     confirmation",
                    asked.describe(&method)
                )));
            }
        }
        let op = json!({
            "method": method,
            "url": dest.url,
            "params": params,
            "body": body,
            "body_type": body_type,
        });
        out.push(Endpoint { dest, op });
    }
    Ok(out)
}

/// The classes named, checked and without repeats. Empty means all of them.
pub(crate) fn parse_classes(named: Option<Vec<String>>) -> Result<Vec<String>, Refusal> {
    let mut classes: Vec<String> = Vec::new();
    for c in named.unwrap_or_default() {
        let c = c.trim().to_ascii_lowercase();
        if !CLASSES.contains(&c.as_str()) {
            return Err(Refusal::invalid(format!(
                "unknown class {:?}; the classes are {}",
                untrusted::clean(&c, 40),
                CLASSES.join(", ")
            )));
        }
        if !classes.contains(&c) {
            classes.push(c);
        }
    }
    Ok(classes)
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
    let eps = endpoints(&a)?;

    let pending = mcp
        .precheck(TrafficRequest {
            tool: "test_injection",
            dests: eps.iter().map(|e| e.dest.clone()).collect(),
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

    // One scan is one origin on one connection, the way plessor's own CLI batches.
    let origin = eps[0].dest.origin();
    let mut origins: Vec<String> = eps.iter().map(|e| e.dest.origin()).collect();
    origins.sort();
    origins.dedup();
    if origins.len() > 1 {
        return Err(Refusal::invalid(format!(
            "these endpoints span {} origins ({}); make one test_injection call per origin",
            origins.len(),
            origins
                .iter()
                .map(|o| untrusted::clean(o, 200))
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    let write = a.test_writes.then(|| WriteAsk {
        remember: None,
        message: format!(
            "test_injection with test_writes will send DELETE, PUT and PATCH requests to {} \
             ({} endpoints). These can change or destroy data.",
            untrusted::clean(&origin, 200),
            eps.len()
        ),
        kind: AskKind::Write,
    });
    let plan = Plan {
        tool: "test_injection",
        target: origin,
        run: Run::Inject {
            endpoints: eps.iter().map(|e| e.op.clone()).collect(),
            classes,
            auth: None,
            scope: mcp.scope.entries.clone(),
        },
        shown_endpoints: eps.iter().map(|e| e.dest.url.clone()).collect(),
        test_writes: a.test_writes,
        source: None,
        wait,
        write,
        on_start: None,
    };
    start_scan(mcp, pending, plan, peer, ct, note).await
}

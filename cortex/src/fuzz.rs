//! Structure / type fuzzing: exercise an operation's KNOWN request shape with mutations a value-
//! injection pass never tries -- wrong-typed values (type confusion) and unsolicited privileged
//! fields (mass assignment) -- and read the result off a differential oracle.
//!
//! This is distinct from `inject` (which puts injection payloads into a field's VALUE to find
//! SQLi/XSS/etc): here the whole typed body is the unit, and the bug is in how the server binds or
//! coerces the request, not in a string payload. It needs the typed shape, so it runs on operations
//! that have one (from a spec, capture, or discovery).

use crate::engine::AuthSpec;
use crate::finding::Finding;
use crate::inject::InjEndpoint;
use crate::probe::{self, is_server_error, json_typed, typed_default};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::mpsc;
use transport::Client;

#[derive(Debug, Deserialize)]
pub struct FuzzParams {
    #[serde(default)]
    pub endpoints: Vec<InjEndpoint>,
    #[serde(default = "d_timeout")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub target: String,
    #[serde(default = "d_true")]
    pub evasive: bool,
    #[serde(default)]
    pub identify: Option<String>,
    #[serde(default)]
    pub auth: Option<AuthSpec>,
    /// Which classes to run: "typefuzz" (type confusion) | "massassign"; empty/null = all.
    #[serde(default, deserialize_with = "crate::probe::de_null_seq")]
    pub classes: Vec<String>,
}
fn d_timeout() -> u64 {
    12_000
}
fn d_true() -> bool {
    true
}

const MAX_ENDPOINTS: usize = 300;
const MAX_FIELDS_PER_EP: usize = 24;

pub async fn run(params: FuzzParams, tx: mpsc::UnboundedSender<Value>) {
    let _ = tx.send(json!({"type":"ack","target": params.target}));
    if params.endpoints.is_empty() {
        let _ = tx.send(json!({"type":"error","message":"structure fuzzing needs at least one endpoint with a known body shape"}));
        let _ = tx.send(json!({"type":"done","found":0}));
        return;
    }
    let want = |c: &str| params.classes.is_empty() || params.classes.iter().any(|x| x == c);
    let client = match probe::build_client(
        params.evasive,
        params.identify.clone(),
        params.auth.as_ref(),
        &params.target,
        params.timeout_ms,
        3000,
    ) {
        Some(c) => c,
        None => {
            let _ = tx.send(json!({"type":"error","message":"client build failed"}));
            return;
        }
    };

    let mut found = 0i64;
    let mut done = 0i64;
    let total = params.endpoints.len().min(MAX_ENDPOINTS) as i64;

    for ep in params.endpoints.iter().take(MAX_ENDPOINTS) {
        // A JSON body shape is required to build a valid baseline to mutate against.
        if ep.body_type.eq_ignore_ascii_case("json") && !ep.body.is_empty() {
            if want("typefuzz") {
                for f in probe_typefuzz(&client, ep).await {
                    let _ = tx.send(json!({"type":"finding","data":f}));
                    found += 1;
                }
            }
            if want("massassign") {
                for f in probe_massassign(&client, ep).await {
                    let _ = tx.send(json!({"type":"finding","data":f}));
                    found += 1;
                }
            }
        }
        done += 1;
        if done % 3 == 0 || done == total {
            let _ = tx.send(json!({"type":"progress","processed":done,"total":total}));
        }
    }
    let _ = tx.send(json!({"type":"done","found":found}));
}

/// The method to actually send a body with (a body-bearing GET is promoted to POST).
fn base_method(ep: &InjEndpoint) -> String {
    let m = ep.method.to_uppercase();
    if m == "GET" { "POST".to_string() } else { m }
}

/// A well-typed baseline JSON body from the operation's known fields, so mutations are the ONLY
/// difference from a valid request.
fn build_base_body(ep: &InjEndpoint) -> serde_json::Map<String, Value> {
    let mut m = serde_json::Map::new();
    for f in &ep.body {
        let base = if f.value.is_empty() {
            typed_default(f.ty.as_deref()).to_string()
        } else {
            f.value.clone()
        };
        m.insert(f.name.clone(), json_typed(&base, f.ty.as_deref()));
    }
    m
}

/// Type confusion: send a wrong-typed value (an array/object where a scalar is expected, etc.) for
/// each field. A mutation that produces a server error (5xx / stack trace) the well-typed baseline
/// did not - reproduced - is an unhandled-input-type bug.
async fn probe_typefuzz(client: &Client, ep: &InjEndpoint) -> Vec<Value> {
    let mut out = Vec::new();
    let method = base_method(ep);
    let base = build_base_body(ep);
    let base_body = Value::Object(base.clone()).to_string();
    let baseline = match probe::send(
        client,
        &method,
        &ep.url,
        Some((&base_body, "application/json")),
    )
    .await
    {
        Some(r) => r,
        None => return out,
    };
    if is_server_error(baseline.status, &baseline.body) {
        return out; // already erroring: no usable oracle
    }
    for f in ep.body.iter().take(MAX_FIELDS_PER_EP) {
        let ty = f.ty.as_deref().unwrap_or("string");
        let wrongs: Vec<Value> = match ty {
            "integer" | "number" => vec![json!(["x"]), json!({ "x": 1 })],
            "boolean" => vec![json!("maybe"), json!([true])],
            "array" => vec![json!("notarray"), json!(1)],
            "object" => vec![json!("notobject"), json!([1])],
            _ => vec![json!([1, 2, 3]), json!({ "x": 1 })], // string / unknown
        };
        for w in wrongs {
            let mut m = base.clone();
            m.insert(f.name.clone(), w.clone());
            let body = Value::Object(m).to_string();
            let r = match probe::send(client, &method, &ep.url, Some((&body, "application/json")))
                .await
            {
                Some(r) => r,
                None => continue,
            };
            if is_server_error(r.status, &r.body) {
                let again =
                    probe::send(client, &method, &ep.url, Some((&body, "application/json"))).await;
                if again
                    .map(|a| is_server_error(a.status, &a.body))
                    .unwrap_or(false)
                {
                    out.push(
                        Finding::new(
                            "cortex-fuzz",
                            "type_confusion",
                            "Unhandled input type (type confusion)",
                            "medium",
                            &ep.url,
                        )
                        .method(&method)
                        .param(&f.name)
                        .location("body")
                        .describe(format!(
                            "Sending `{}` where body field `{}` expects a {} caused a server error (5xx / stack trace) that a well-typed request did not, and it reproduced - unvalidated input of the wrong type reaches the handler.",
                            w, f.name, ty
                        ))
                        .build(),
                    );
                    break;
                }
            }
        }
    }
    out
}

/// Privileged/binding fields a mass-assignment-vulnerable create/update endpoint might accept.
const PRIV_FIELDS: &[&str] = &[
    "is_admin",
    "isAdmin",
    "admin",
    "role",
    "roles",
    "user_role",
    "id",
    "user_id",
    "userId",
    "owner",
    "ownerId",
    "owner_id",
    "account_id",
    "is_verified",
    "verified",
    "email_verified",
    "is_active",
    "balance",
    "credit",
    "credits",
    "price",
    "amount",
    "permissions",
    "grant",
    "scope",
    "status",
];

/// Mass assignment (BOPLA): add unsolicited privileged fields to the body; if the server reflects a
/// value back (accepted + persisted) while a CONTROL junk field is NOT reflected, the endpoint binds
/// client-supplied fields it should not. The control calibration rejects endpoints that simply echo
/// the whole request body (which would otherwise be a false positive).
async fn probe_massassign(client: &Client, ep: &InjEndpoint) -> Vec<Value> {
    let mut out = Vec::new();
    let method = base_method(ep);
    let base = build_base_body(ep);
    let existing: std::collections::HashSet<String> = base.keys().cloned().collect();

    let mut m = base.clone();
    let mut sentinels: Vec<(String, String)> = Vec::new();
    for (i, name) in PRIV_FIELDS.iter().enumerate() {
        if existing.contains(*name) {
            continue;
        }
        let s = format!("cfxma{i}z");
        m.insert((*name).to_string(), Value::String(s.clone()));
        sentinels.push(((*name).to_string(), s));
    }
    if sentinels.is_empty() {
        return out;
    }
    let control = "cfxctrljunk9z";
    m.insert(
        "cfx_unlikely_control_field".to_string(),
        Value::String(control.to_string()),
    );

    let body = Value::Object(m).to_string();
    let r = match probe::send(client, &method, &ep.url, Some((&body, "application/json"))).await {
        Some(r) => r,
        None => return out,
    };
    if r.body.contains(control) {
        return out; // endpoint reflects arbitrary input; no reliable oracle
    }
    for (name, s) in &sentinels {
        if r.body.contains(s) {
            out.push(
                Finding::new(
                    "cortex-fuzz",
                    "mass_assignment",
                    "Mass assignment (unexpected field bound)",
                    "high",
                    &ep.url,
                )
                .method(&method)
                .param(name.as_str())
                .location("body")
                .describe(format!(
                    "An unsolicited `{name}` field added to the request body was accepted and reflected in the response, while a control junk field was not - the endpoint binds client-supplied fields it should not expose, enabling privilege/field tampering (BOPLA)."
                ))
                .build(),
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inject::BodyField;

    #[test]
    fn build_base_body_is_well_typed() {
        let ep = InjEndpoint {
            method: "POST".into(),
            url: "https://api.x/pets".into(),
            params: vec![],
            path_params: vec![],
            body: vec![
                BodyField {
                    name: "name".into(),
                    value: String::new(),
                    ty: Some("string".into()),
                },
                BodyField {
                    name: "ownerId".into(),
                    value: String::new(),
                    ty: Some("integer".into()),
                },
                BodyField {
                    name: "enabled".into(),
                    value: String::new(),
                    ty: Some("boolean".into()),
                },
            ],
            body_type: "json".into(),
        };
        let m = build_base_body(&ep);
        assert_eq!(m["name"], Value::String("test".into()));
        assert_eq!(m["ownerId"], Value::from(1i64));
        assert_eq!(m["enabled"], Value::Bool(true));
        assert_eq!(base_method(&ep), "POST");
    }
}

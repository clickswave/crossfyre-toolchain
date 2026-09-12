//! GraphQL security engine. Where the REST engines think in (method x path) + params, GraphQL has a
//! single endpoint and the real operations live inside the request body, so this engine speaks
//! GraphQL natively: it live-introspects the schema, then runs GraphQL-specific checks that have no
//! REST equivalent (introspection exposure, field-suggestion leakage, alias/batch amplification) plus
//! argument-level injection (SQLi error-based, OS command injection OAST-confirmed) on every root
//! field. All probes are read-only where possible; confirmation is by DB-error signature or an
//! out-of-band callback, never a destructive payload.

use crate::engine::{AuthSpec, OastSpec};
use crate::probe::{self, de_null_seq, is_sql_error};
use cfx_finding::Finding;
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Duration;
use tokio::sync::mpsc;
use transport::Client;

#[derive(Debug, Deserialize)]
pub struct GraphqlParams {
    #[serde(default)]
    pub target: String,
    /// The GraphQL route. Absolute URL, or a path joined onto `target`. Defaults to `/graphql`.
    #[serde(default)]
    pub endpoint: String,
    #[serde(default = "d_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "d_true")]
    pub evasive: bool,
    #[serde(default)]
    pub identify: Option<String>,
    #[serde(default)]
    pub auth: Option<AuthSpec>,
    #[serde(default)]
    pub oast: Option<OastSpec>,
    /// introspection | suggestions | dos | batching | sensitive | authz | injection ; empty/null = all.
    #[serde(default, deserialize_with = "de_null_seq")]
    pub classes: Vec<String>,
    /// Allow the BFLA probe to invoke privileged MUTATIONS (state-changing). Off by default: only
    /// read-only privileged queries are exercised, mirroring the REST authz engine's safety rail.
    #[serde(default)]
    pub test_writes: bool,
    /// Refuse private and reserved destinations at connect time. Absent = false,
    /// which is what an authorised customer scan gets: reaching your own
    /// internal network from your own node is the product. The free public
    /// tools set it, because there the caller is anonymous and the egress is
    /// ours.
    #[serde(default)]
    pub block_internal: bool,
}
fn d_timeout() -> u64 {
    12_000
}
fn d_true() -> bool {
    true
}

const INTROSPECT: &str = r#"{"query":"{ __schema { queryType { name fields { name args { name type { kind name ofType { kind name ofType { kind name } } } } type { kind name ofType { kind name } } } } mutationType { name fields { name args { name type { kind name ofType { kind name ofType { kind name } } } } type { kind name ofType { kind name } } } } types { name kind fields { name } } } }"}"#;

/// Field names that should never be exposed in a schema/response (credentials + secrets).
static SENSITIVE_FIELD: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "accesstoken",
    "access_token",
    "privatekey",
    "private_key",
    "hash",
    "salt",
    "ssn",
    "creditcard",
    "credit_card",
    "cvv",
];

/// One root field we can exercise: its operation type, name, string/ID args, and whether its return
/// type needs a `{ __typename }` selection set (object-ish) or must be bare (scalar/enum).
struct Field {
    op: &'static str, // "query" | "mutation"
    name: String,
    string_args: Vec<String>,
    needs_selection: bool,
}

pub async fn run(params: GraphqlParams, tx: mpsc::UnboundedSender<Value>) {
    let url = resolve_url(&params.target, &params.endpoint);
    let _ = tx.send(json!({"type":"ack","target": url}));
    let want = |c: &str| params.classes.is_empty() || params.classes.iter().any(|x| x == c);

    let client = match probe::build_client(probe::ClientOpts {
        evasive: params.evasive,
        identify: params.identify.clone(),
        auth: params.auth.as_ref(),
        target: &params.target,
        timeout_ms: params.timeout_ms,
        min_timeout_ms: 8000,
        block_internal: params.block_internal,
    }) {
        Some(c) => c,
        None => {
            let _ = tx.send(json!({"type":"error","message":"client build failed"}));
            let _ = tx.send(json!({"type":"done","found":0}));
            return;
        }
    };
    let oast = match &params.oast {
        Some(s) if !s.domains.is_empty() && !s.api_url.is_empty() => {
            crate::oast::OastClient::from_spec(s.domains.clone(), &s.api_url)
        }
        _ => crate::oast::OastClient::from_env(),
    };
    // One correlation for the whole GraphQL pass, and one queue of findings
    // waiting on it.
    let oob_reg = match oast.as_ref() {
        Some(oc) => oc.register(&client).await,
        None => None,
    };
    let oob_queue: crate::inject::OobQueue = Default::default();

    let mut found = 0i64;

    // --- 1. Introspection exposure + schema harvest -------------------------------------------
    let schema_resp = post(&client, &url, INTROSPECT).await;
    let schema_json = schema_resp
        .as_ref()
        .and_then(|r| serde_json::from_str::<Value>(&r.body).ok());
    let has_schema = schema_json
        .as_ref()
        .and_then(|v| v.pointer("/data/__schema"))
        .is_some();

    if has_schema && want("introspection") {
        let _ = tx.send(finding(
            "graphql_introspection",
            "GraphQL introspection enabled",
            "medium",
            &url, "POST",
            "The server answered a full `__schema` introspection query in production. This hands an attacker the complete API map -- every type, field, argument, and mutation -- turning targeted attacks (injection, BOLA, hidden admin mutations) into a lookup. Disable introspection outside development."
        ).event());
        found += 1;
    }

    // --- 2. Field-suggestion leakage (works even when introspection is off) --------------------
    if want("suggestions") {
        let q = r#"{"query":"{ __cfxTypoField_zz }"}"#;
        if let Some(r) = post(&client, &url, q).await {
            let low = r.body.to_lowercase();
            if low.contains("did you mean") {
                let _ = tx.send(finding(
                    "graphql_suggestions",
                    "GraphQL field-suggestion leakage",
                    "low",
                    &url, "POST",
                    "An unknown field triggered a 'Did you mean ...' suggestion. When introspection is disabled this still lets an attacker recover the schema field by field. Turn off field suggestions in production."
                ).event());
                found += 1;
            }
        }
    }

    let fields = schema_json.as_ref().map(parse_fields).unwrap_or_default();

    // --- 4. Alias-based amplification (DoS surface) --------------------------------------------
    if want("dos") && !fields.is_empty() {
        // A cheap, no-arg-friendly field aliased many times: if the server resolves all of them in
        // one request it has no query-cost limit, so a single request can be amplified into
        // thousands of resolver calls (batching/alias DoS).
        if let Some(f) = fields
            .iter()
            .find(|f| f.op == "query" && f.string_args.is_empty())
        {
            let aliases: String = (0..100)
                .map(|i| format!("a{i}: __typename"))
                .collect::<Vec<_>>()
                .join(" ");
            let q = json!({ "query": format!("{{ {aliases} }}") }).to_string();
            if let Some(r) = post(&client, &url, &q).await {
                if r.status == 200 && r.body.matches("\"a99\"").count() >= 1 {
                    let _ = tx.send(finding(
                        "graphql_dos",
                        "GraphQL query-cost / alias amplification",
                        "medium",
                        &url, "POST",
                        &format!("A single request aliasing `{}` 100 times was fully resolved. With no query-cost, depth, or alias limit, one small request multiplies into thousands of resolver calls, enabling denial of service (OWASP API4). Enforce query cost / depth limits.", f.name)
                    ).event());
                    found += 1;
                }
            }
        }
    }

    // --- 5. Array-batching amplification (auth brute-force enabler) ----------------------------
    if want("batching") {
        // A JSON array of N operations in ONE request: if the server runs them all it enables
        // batched brute-force (thousands of login/OTP attempts per request, bypassing rate limits).
        let one = json!({ "query": "{ __typename }" });
        let batch = Value::Array(vec![one.clone(); 10]).to_string();
        if let Some(r) = post(&client, &url, &batch).await {
            if r.status == 200 {
                if let Ok(Value::Array(arr)) = serde_json::from_str::<Value>(&r.body) {
                    if arr.len() >= 2 {
                        let _ = tx.send(finding(
                            "graphql_batching",
                            "GraphQL query batching enabled",
                            "medium",
                            &url, "POST",
                            "The endpoint executed a JSON array of 10 operations in a single request. Query batching lets an attacker run thousands of login / OTP / password-reset attempts per request, defeating per-request rate limits (OWASP API4). Disable batching or count each batched op against the limit."
                        ).event());
                        found += 1;
                    }
                }
            }
        }
    }

    // --- 6. Sensitive fields exposed in the schema (design-level data exposure) ----------------
    if want("sensitive") {
        if let Some(schema) = &schema_json {
            let mut hits: Vec<String> = Vec::new();
            if let Some(types) = schema
                .pointer("/data/__schema/types")
                .and_then(|v| v.as_array())
            {
                for t in types {
                    let tname = t.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    if tname.starts_with("__") {
                        continue;
                    }
                    if let Some(tfields) = t.get("fields").and_then(|v| v.as_array()) {
                        for f in tfields {
                            let fname = f.get("name").and_then(|v| v.as_str()).unwrap_or("");
                            let low = fname.to_lowercase().replace(['_', '-'], "");
                            if SENSITIVE_FIELD.iter().any(|s| low == s.replace('_', "")) {
                                hits.push(format!("{tname}.{fname}"));
                            }
                        }
                    }
                }
            }
            if !hits.is_empty() {
                hits.sort();
                hits.dedup();
                hits.truncate(20);
                let _ = tx.send(finding(
                    "graphql_sensitive_field",
                    "Sensitive fields exposed in GraphQL schema",
                    "medium",
                    &url, "POST",
                    &format!("The schema exposes credential/secret fields that clients can request: {}. Query-able password/token/secret fields are a data-exposure and account-takeover risk - remove them from the API type or gate them behind field-level authorization.", hits.join(", ")),
                ).event());
                found += 1;
            }
        }
    }

    // --- 6b. Function-level authorization (BFLA, API5): privileged operations reachable ---------
    // Root fields whose name reads privileged (admin/delete/system/createUser/...) that resolve for
    // THIS identity (anon by default) without an authorization error are broken function-level
    // authorization: an unauthenticated or low-privilege caller can invoke an admin operation.
    if want("authz") && !fields.is_empty() {
        // Privileged operations that were named and deliberately not invoked.
        let mut declined: Vec<String> = Vec::new();
        for f in &fields {
            if !is_privileged_name(&f.name) {
                continue;
            }
            // Whether invoking this is safe is decided by what it DOES, not by
            // which GraphQL operation type it is filed under.
            //
            // The rule here used to be "read-only queries are always safe to
            // probe", and GraphQL guarantees no such thing: a query is a query
            // because the schema author said so. dvga files `systemUpdate`,
            // `deleteAllPastes` and `systemDiagnostics(cmd:)` as queries;
            // `systemUpdate` runs `python3 setup.py` through os.popen. Measured:
            // a single `{systemUpdate}` hangs for 25 seconds and leaves the
            // application answering in 3.2s where it answered in 3ms, and a full
            // pass left it not answering at all. A scanner that does that to a
            // customer's API has caused an outage to report a finding.
            //
            // So a field whose NAME names an action is treated exactly like a
            // mutation: reported as present, never invoked, unless the caller
            // opted into writes. The cost is honest and small - a destructive
            // operation that is genuinely unprotected goes unconfirmed rather
            // than unmentioned - and it is the same trade the crawler and the
            // injector already make for links and endpoints.
            if (f.op == "mutation" || executes_something(&f.name)) && !params.test_writes {
                declined.push(f.name.clone());
                continue;
            }
            let doc = build_doc(f, "", "1"); // benign args; we only care whether authz blocks it
            if let Some(r) = post(&client, &url, &doc).await {
                if r.status == 200 && !denied(&r.body) && resolver_ran(&r.body, &f.name) {
                    let _ = tx.send(finding(
                        "graphql_bfla",
                        "Privileged GraphQL operation reachable without authorization",
                        "high",
                        &url, "POST",
                        &format!("The privileged {} `{}` resolved for an unauthenticated/low-privilege caller with no authorization error. Function-level access control is missing on a sensitive operation (OWASP API5: BFLA) - an attacker can invoke admin/destructive functionality directly.", f.op, f.name),
                    ).param(&f.name).event());
                    found += 1;
                }
            }
        }
        if !declined.is_empty() {
            declined.sort();
            declined.dedup();
            let _ = tx.send(json!({"type":"log","message": format!(
                "{} privileged operation(s) were found and NOT invoked: {}. Their names say they \
                 perform an action, and the only way to prove an authorization check is missing on \
                 one is to call it, which on this schema means running it. Whether they are \
                 protected is therefore untested here, not clean. Re-run with writes enabled \
                 against a target you are willing to change.",
                declined.len(),
                declined.join(", ")
            )}));
        }
    }

    // --- 7. Argument injection (SQLi error-based, cmdi OAST-confirmed) -------------------------
    // Runs LAST: it is the slow phase (a blind-cmdi OAST poll per string arg), so the fast
    // schema-level checks above always emit even if a per-field OAST wait runs long.
    if want("injection") && !fields.is_empty() {
        for f in &fields {
            for arg in &f.string_args {
                if let Some(fd) = probe_field_injection(
                    &client,
                    &url,
                    f,
                    arg,
                    oast.as_ref(),
                    oob_reg.as_ref(),
                    Some(&oob_queue),
                )
                .await
                {
                    let _ = tx.send(json!({"type":"finding","data": fd}));
                    found += 1;
                }
            }
        }
    }

    // Out-of-band callbacks, collected once for the whole pass.
    if let (Some(oc), Some(reg)) = (oast.as_ref(), oob_reg.as_ref()) {
        let pending: Vec<crate::inject::PendingOob> = oob_queue
            .lock()
            .map(|mut v| std::mem::take(&mut *v))
            .unwrap_or_default();
        if !pending.is_empty() {
            let mut hosts: Vec<String> = Vec::new();
            for wait in [0u64, 2000, 4000] {
                if wait > 0 {
                    tokio::time::sleep(Duration::from_millis(wait)).await;
                }
                hosts = oc.poll_hosts(&client, reg).await;
                if !hosts.is_empty() {
                    break;
                }
            }
            for p in pending {
                if hosts.iter().any(|h| h.contains(&p.marker)) {
                    let _ = tx.send(json!({"type":"finding","data": p.finding}));
                    found += 1;
                }
            }
        }
        oc.deregister(&client, reg).await;
    }

    let _ = tx.send(json!({"type":"done","found":found}));
}

/// Root-field name substrings that read as privileged/administrative or destructive.
static PRIV_NAME: &[&str] = &[
    "admin",
    "delete",
    "remove",
    "destroy",
    "drop",
    "system",
    "config",
    "setting",
    "debug",
    "exec",
    "run",
    "command",
    "shell",
    "grant",
    "revoke",
    "promote",
    "role",
    "permission",
    "createuser",
    "updateuser",
    "deleteuser",
    "adduser",
    "ban",
    "suspend",
    "impersonate",
    "import",
    "restore",
    "reset",
    "internal",
    "audit",
    "diagnostic",
    "update",
];

fn is_privileged_name(name: &str) -> bool {
    let low = name.to_lowercase();
    PRIV_NAME.iter().any(|k| low.contains(k))
}

/// The GraphQL response denied the operation (authorization error), so it is NOT a BFLA hit.
fn denied(body: &str) -> bool {
    let low = body.to_lowercase();
    low.contains("unauthorized")
        || low.contains("forbidden")
        || low.contains("not authorized")
        || low.contains("must be logged in")
        || low.contains("authentication required")
        || low.contains("permission denied")
        || low.contains("access denied")
        || low.contains("login required")
        || low.contains("not allowed")
}

/// The named resolver actually ran (returned data, or errored on something other than authorization -
/// e.g. a validation/type error means auth let the call THROUGH to the resolver).
fn resolver_ran(body: &str, field: &str) -> bool {
    match serde_json::from_str::<Value>(body) {
        Ok(v) => {
            let data_present = v
                .pointer(&format!("/data/{field}"))
                .map(|d| !d.is_null())
                .unwrap_or(false);
            // a non-auth error still means auth did not block the call
            let non_auth_error = v
                .get("errors")
                .and_then(|e| e.as_array())
                .map(|_| !denied(body))
                .unwrap_or(false);
            data_present || non_auth_error
        }
        Err(_) => false,
    }
}

/// Does this field's name say it performs an action rather than answering a
/// question? Same vocabulary the crawler and the injector use, for the same
/// reason: a verb is the only evidence a schema gives about side effects.
fn executes_something(name: &str) -> bool {
    const VERBS: &[&str] = &[
        "delete",
        "destroy",
        "remove",
        "drop",
        "purge",
        "truncate",
        "wipe",
        "reset",
        "update",
        "upgrade",
        "install",
        "import",
        "restart",
        "reboot",
        "shutdown",
        "revoke",
        "disable",
        "enable",
        "toggle",
        "deactivate",
        "create",
        "send",
        "execute",
        "run",
        "exec",
        "kill",
        "clear",
    ];
    // camelCase and snake_case both split into words here: `deleteAllPastes`
    // and `delete_all_pastes` give the same first token.
    let mut words: Vec<String> = Vec::new();
    let mut cur = String::new();
    for ch in name.chars() {
        if ch == '_' || ch == '-' {
            if !cur.is_empty() {
                words.push(std::mem::take(&mut cur));
            }
        } else if ch.is_ascii_uppercase() && !cur.is_empty() {
            words.push(std::mem::take(&mut cur));
            cur.push(ch.to_ascii_lowercase());
        } else {
            cur.push(ch.to_ascii_lowercase());
        }
    }
    if !cur.is_empty() {
        words.push(cur);
    }
    words.iter().any(|w| VERBS.contains(&w.as_str()))
}

fn resolve_url(target: &str, endpoint: &str) -> String {
    if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
        return endpoint.to_string();
    }
    let base = target.trim_end_matches('/');
    if endpoint.is_empty() {
        format!("{base}/graphql")
    } else {
        format!("{base}/{}", endpoint.trim_start_matches('/'))
    }
}

async fn post(client: &Client, url: &str, body: &str) -> Option<probe::Resp> {
    probe::send(client, "POST", url, Some((body, "application/json"))).await
}

/// Unwrap a GraphQL type ref (NON_NULL / LIST wrappers) to the underlying (kind, name).
fn unwrap_type(t: &Value) -> (String, String) {
    let mut cur = t;
    loop {
        let kind = cur.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        let name = cur.get("name").and_then(|v| v.as_str());
        if let Some(n) = name {
            if !n.is_empty() {
                return (kind.to_string(), n.to_string());
            }
        }
        match cur.get("ofType") {
            Some(inner) if !inner.is_null() => cur = inner,
            _ => return (kind.to_string(), String::new()),
        }
    }
}

fn parse_fields(schema: &Value) -> Vec<Field> {
    let mut out = Vec::new();
    for (op, ptr) in [
        ("query", "/data/__schema/queryType/fields"),
        ("mutation", "/data/__schema/mutationType/fields"),
    ] {
        let Some(arr) = schema.pointer(ptr).and_then(|v| v.as_array()) else {
            continue;
        };
        for f in arr {
            let Some(name) = f.get("name").and_then(|v| v.as_str()) else {
                continue;
            };
            if name.starts_with("__") {
                continue;
            }
            let mut string_args = Vec::new();
            if let Some(args) = f.get("args").and_then(|v| v.as_array()) {
                for a in args {
                    let an = a.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    let (_k, tn) = a.get("type").map(unwrap_type).unwrap_or_default();
                    if !an.is_empty() && (tn == "String" || tn == "ID") {
                        string_args.push(an.to_string());
                    }
                }
            }
            let (ret_kind, _ret_name) = f.get("type").map(unwrap_type).unwrap_or_default();
            let needs_selection = matches!(ret_kind.as_str(), "OBJECT" | "INTERFACE" | "UNION");
            out.push(Field {
                op,
                name: name.to_string(),
                string_args,
                needs_selection,
            });
        }
    }
    out
}

/// Build a GraphQL document exercising `field` with `value` placed in `inj_arg` (other string args
/// get a benign filler so required args are satisfied).
fn build_doc(field: &Field, inj_arg: &str, value: &str) -> String {
    let args: String = field
        .string_args
        .iter()
        .map(|a| {
            let v = if a == inj_arg { value } else { "1" };
            format!("{a}: {}", json!(v)) // json! escapes the string literal safely
        })
        .collect::<Vec<_>>()
        .join(", ");
    let call = if args.is_empty() {
        field.name.clone()
    } else {
        format!("{}({})", field.name, args)
    };
    let sel = if field.needs_selection {
        " { __typename }"
    } else {
        ""
    };
    let op_kw = if field.op == "mutation" {
        "mutation"
    } else {
        "query"
    };
    json!({ "query": format!("{op_kw} {{ {call}{sel} }}") }).to_string()
}

/// Does a GraphQL JSON response carry an error whose message looks like a SQL engine error?
fn graphql_sql_error(body: &str) -> bool {
    if is_sql_error(body) {
        return true;
    }
    // GraphQL wraps resolver errors in {"errors":[{"message":"..."}]}; scan those messages.
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| v.get("errors").and_then(|e| e.as_array()).cloned())
        .map(|errs| {
            errs.iter().any(|e| {
                e.get("message")
                    .and_then(|m| m.as_str())
                    .map(is_sql_error)
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

async fn probe_field_injection(
    client: &Client,
    url: &str,
    field: &Field,
    arg: &str,
    oast: Option<&crate::oast::OastClient>,
    oob_reg: Option<&crate::oast::OastReg>,
    oob_queue: Option<&crate::inject::OobQueue>,
) -> Option<Value> {
    // --- error-based SQLi: a single quote that a well-formed value does not trigger ---
    let baseline = post(client, url, &build_doc(field, arg, "1")).await;
    let base_sql = baseline
        .as_ref()
        .map(|r| graphql_sql_error(&r.body))
        .unwrap_or(false);
    if !base_sql {
        let hit = post(client, url, &build_doc(field, arg, "1'")).await;
        if hit
            .as_ref()
            .map(|r| graphql_sql_error(&r.body))
            .unwrap_or(false)
        {
            // confirm: balanced quote should clear the error
            let ctrl = post(client, url, &build_doc(field, arg, "1''")).await;
            let ctrl_clean = ctrl.map(|c| !graphql_sql_error(&c.body)).unwrap_or(false);
            if ctrl_clean {
                return Some(finding(
                    "sqli",
                    "SQL injection via GraphQL argument (error-based)",
                    "high",
                    url,
                    "POST",
                    &format!(
                        "An unbalanced quote in the `{arg}` argument of the `{}` {} produced a database error that a balanced quote did not: the argument reaches a SQL statement unparameterised.",
                        field.name, field.op
                    ),
                )
                // The injected argument, so a consumer can reproduce it without
                // parsing it back out of the prose.
                .param(arg)
                .build());
            }
        }
    }

    // --- OS command injection, output reflected ---
    //
    // The same oracle the HTTP injector reaches for first, and for the same
    // reasons: one request per separator, no sleeps, no OAST budget, and a match
    // is proof rather than evidence. The payload carries `$((a*b))`
    // un-evaluated, so the product can only appear if a shell computed it.
    //
    // This path had the blind oracle alone, which is a real gap rather than a
    // stylistic one. dvga's `systemDebug(arg:)` runs `ps {arg}` through
    // os.popen and returns the output in the GraphQL response, so `; echo`
    // comes straight back; the blind oracle would only have found it if the
    // container could reach an OAST host, which is a different question from
    // whether the argument reaches a shell.
    {
        let prod = crate::inject::CMDI_ECHO_A * crate::inject::CMDI_ECHO_B;
        let marker = format!("zZcx{prod}xcZz");
        for sep in [";", "|", "&&", "$(", "`"] {
            let close = match sep {
                "$(" => ")",
                "`" => "`",
                _ => "",
            };
            let pl = format!(
                "1{sep}echo zZcx$(({}*{}))xcZz{close}",
                crate::inject::CMDI_ECHO_A,
                crate::inject::CMDI_ECHO_B
            );
            if let Some(r) = post(client, url, &build_doc(field, arg, &pl)).await {
                if r.body.contains(&marker) {
                    return Some(
                        finding(
                            "cmdi",
                            "OS command injection via GraphQL argument (output reflected)",
                            "critical",
                            url,
                            "POST",
                            &format!(
                                "A shell-evaluated arithmetic marker injected into the `{arg}` argument of `{}` came back computed in the response (separator `{sep}`), while the payload only ever carries the un-evaluated expression: the value is executed by a shell.",
                                field.name
                            ),
                        )
                        .param(arg)
                        .build(),
                    );
                }
            }
        }
    }

    // --- blind OS command injection, OAST-confirmed ---
    //
    // Fire and park, for the reason inject.rs does: a schema of any size has
    // many (field, argument) pairs, and blocking four polls on each one to
    // learn that almost none of them reach a shell is the whole scan's time
    // spent waiting on nothing.
    if let (Some(oc), Some(reg), Some(q)) = (oast, oob_reg, oob_queue) {
        let (host, marker) = oc.host_marked(reg);
        for sep in [";", "|", "&&", "$(", "`"] {
            let close = if sep == "$(" {
                ")"
            } else if sep == "`" {
                "`"
            } else {
                ""
            };
            let pl = format!("1{sep}curl http://{host}/g{close}");
            let _ = post(client, url, &build_doc(field, arg, &pl)).await;
            let pl2 = format!("1{sep}nslookup {host}{close}");
            let _ = post(client, url, &build_doc(field, arg, &pl2)).await;
        }
        if let Ok(mut v) = q.lock() {
            v.push(crate::inject::PendingOob {
                marker,
                finding: finding(
                    "cmdi",
                    "OS command injection via GraphQL argument (blind, OAST-confirmed)",
                    "critical",
                    url,
                    "POST",
                    &format!(
                        "A shell metacharacter injected into the `{arg}` argument of `{}` produced an out-of-band callback: the value is passed to a shell.",
                        field.name
                    ),
                )
                .param(arg)
                .build(),
            });
        }
    }
    None
}

/// A GraphQL finding, pre-filled with what every one of them shares. Call sites
/// add what only they know (`.param(arg)` for an injected argument) and finish
/// with `.event()` or `.build()`.
fn finding(
    class: &str,
    name: &str,
    severity: &str,
    url: &str,
    method: &str,
    detail: &str,
) -> Finding {
    Finding::new("cortex-graphql", class, name, severity, url)
        .method(method)
        .location("graphql")
        .describe(detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unwraps_nested_type() {
        let t = json!({"kind":"NON_NULL","name":null,"ofType":{"kind":"SCALAR","name":"String","ofType":null}});
        assert_eq!(unwrap_type(&t), ("SCALAR".into(), "String".into()));
    }

    #[test]
    fn builds_query_with_selection_and_escapes() {
        let f = Field {
            op: "query",
            name: "paste".into(),
            string_args: vec!["id".into()],
            needs_selection: true,
        };
        let doc = build_doc(&f, "id", "1\" or \"1");
        assert!(doc.contains("paste(id:"));
        assert!(doc.contains("__typename"));
        // the quote must be escaped inside the JSON-encoded query string
        assert!(!doc.contains("or \"1\" {"));
    }

    #[test]
    fn resolves_endpoint() {
        assert_eq!(resolve_url("http://x.test", ""), "http://x.test/graphql");
        assert_eq!(
            resolve_url("http://x.test/", "/api/gql"),
            "http://x.test/api/gql"
        );
        assert_eq!(
            resolve_url("http://x.test", "https://y.test/graphql"),
            "https://y.test/graphql"
        );
    }

    #[test]
    fn a_field_whose_name_performs_an_action_is_not_invoked() {
        // Every one of these is filed as a QUERY in dvga's schema, and each one
        // does something. That is the whole reason operation type is not the
        // test: `systemUpdate` runs `python3 setup.py`.
        for n in [
            "systemUpdate",
            "deleteAllPastes",
            "importPaste",
            "createUser",
            "delete_all_pastes",
            "resetDatabase",
            "shutdown",
            "revokeToken",
        ] {
            assert!(
                executes_something(n),
                "{n} should not be invoked by default"
            );
        }
    }

    #[test]
    fn a_field_that_answers_a_question_is_still_probed() {
        // Refusing these would cost the BFLA check its whole point.
        for n in [
            "audits",
            "systemHealth",
            "systemDiagnostics",
            "me",
            "users",
            "pastes",
            "paste",
            "search",
            "readAndBurn",
            "systemDebug",
        ] {
            assert!(!executes_something(n), "{n} should still be probed");
        }
    }

    #[test]
    fn camel_and_snake_split_the_same_way() {
        assert!(executes_something("deleteAllPastes"));
        assert!(executes_something("delete_all_pastes"));
        assert!(!executes_something("undeleted"));
        assert!(!executes_something("createdAt"));
    }
}

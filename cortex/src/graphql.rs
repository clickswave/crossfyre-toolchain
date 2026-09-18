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

const INTROSPECT: &str = r#"{"query":"{ __schema { queryType { name fields { name args { name type { kind name ofType { kind name ofType { kind name } } } } type { kind name ofType { kind name } } } } mutationType { name fields { name args { name type { kind name ofType { kind name ofType { kind name } } } } type { kind name ofType { kind name } } } } types { name kind fields { name args { name type { kind name ofType { kind name ofType { kind name } } } } type { kind name ofType { kind name ofType { kind name } } } } } } }"}"#;

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
#[derive(Clone)]
struct Field {
    op: &'static str, // "query" | "mutation"
    name: String,
    /// The named object type this field returns, when it returns one. Needed to
    /// look the type up in the schema and decide whether it is data or a
    /// namespace.
    ret_type_name: Option<String>,
    /// The namespace this operation lives inside, when it is not a root field.
    /// Mature GraphQL APIs group operations by domain, so the thing worth
    /// calling is `system { info }` rather than a root field of its own.
    parent: Option<String>,
    /// A real scalar field of the return type, to select instead of
    /// `__typename`. Selecting `__typename` asks the server to name a type and
    /// proves nothing was read: Wiki.js authorizes the scalar leaves of
    /// `SystemInfo`, so `system { info { __typename } }` answers an anonymous
    /// caller with data while `system { info { hostname } }` is refused.
    selection: Option<String>,
    /// Whether the field takes any arguments at all. A field that takes
    /// arguments is an operation, never a namespace: a container has nothing to
    /// parameterise. Without this, a Relay-style mutation payload (an object
    /// wrapping the created record) looks exactly like a namespace, and dvga's
    /// `createUser(username, email, password)` was walked into as one.
    has_args: bool,
    string_args: Vec<String>,
    needs_selection: bool,
}

impl Field {
    /// How to name this operation to a human, and the shape its response path
    /// takes: `system.info` for a namespaced one, `audits` for a root field.
    fn path_name(&self) -> String {
        match &self.parent {
            Some(p) => format!("{p}.{}", self.name),
            None => self.name.clone(),
        }
    }
}

pub async fn run(params: GraphqlParams, tx: mpsc::UnboundedSender<Value>) {
    let url = resolve_url(&params.target, &params.endpoint);
    let _ = tx.send(json!({"type":"ack","target": url}));
    let want = |c: &str| params.classes.is_empty() || params.classes.iter().any(|x| x == c);

    // Every field on GraphqlParams has a default, so a job that loses its
    // target (a renamed field, a null, params nested one level too deep)
    // deserializes cleanly into a scan of nothing. It then reaches the end and
    // reports `found: 0`, which is recorded downstream as a clean target. This
    // engine was the only one that could do that: the other five need
    // endpoints or identities they cannot default, so they already refuse.
    if !url.starts_with("http://") && !url.starts_with("https://") {
        let _ = tx.send(json!({
            "type": "log",
            "message": format!(
                "no GraphQL endpoint to test: target {:?} and endpoint {:?} resolve to {url:?}, \
                 which is not an absolute URL. Nothing was run, so this is not a clean result.",
                params.target, params.endpoint
            )
        }));
        let _ = tx.send(json!({"type":"done","found":0}));
        return;
    }

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
    // an UNAUTHENTICATED caller without an authorization error are broken function-level
    // authorization: anybody at all can invoke an admin operation.
    //
    // The probe used to send these with whatever credential the job supplied,
    // and then report every privileged field that answered. Give it an admin
    // token, which is an ordinary thing to do on an authenticated scan and what
    // the REST authz engine asks for, and it reports the administrator for
    // administering: measured against a correctly-authorized schema, six
    // privileged fields produced six high-severity findings as `admin` and one
    // as `user`, and the one was the deliberately unprotected field. Five of the
    // six were the API working exactly as designed, each described as having
    // "resolved for an unauthenticated/low-privilege caller", which was not
    // true of the caller the engine had used.
    //
    // A single identity cannot support that claim. The REST engine settles it
    // with a role-labelled identity matrix; GraphQL params carry one unlabelled
    // credential, so there is no way to know whether this caller is supposed to
    // hold these rights. What can be decided from one request is whether a
    // caller holding NO credential can invoke the operation, and that is the
    // claim the finding makes, so that is the request to send.
    if want("authz") && !fields.is_empty() {
        // Deliberately credential-free, whatever the job supplied. The schema
        // above is still harvested with the job's auth, because plenty of APIs
        // will not introspect for a stranger.
        let anon = probe::build_client(probe::ClientOpts {
            evasive: params.evasive,
            identify: params.identify.clone(),
            auth: None,
            target: &params.target,
            timeout_ms: params.timeout_ms,
            min_timeout_ms: 8000,
            block_internal: params.block_internal,
        });
        // Privileged operations that were named and deliberately not invoked.
        let mut declined: Vec<String> = Vec::new();
        let probes = schema_json
            .as_ref()
            .map(|sj| authz_probes(sj, &fields))
            .unwrap_or_default();
        for f in &probes {
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
                declined.push(f.path_name());
                continue;
            }
            let Some(anon) = anon.as_ref() else { continue };
            let doc = build_doc(f, "", "1"); // benign args; we only care whether authz blocks it
            if let Some(r) = post(anon, &url, &doc).await {
                let name = f.path_name();
                if r.status == 200 && !denied(&r.body) && resolver_ran(&r.body, f) {
                    let _ = tx.send(finding(
                        "graphql_bfla",
                        "Privileged GraphQL operation reachable without authorization",
                        "high",
                        &url, "POST",
                        &format!("The privileged {} `{}` resolved for a caller sending no credential at all, with no authorization error. Function-level access control is missing on a sensitive operation (OWASP API5: BFLA) - anyone who can reach the endpoint can invoke admin/destructive functionality directly.", f.op, name),
                    ).param(&name).event());
                    found += 1;
                }
            }
        }
        if anon.is_none() {
            let _ = tx.send(json!({"type":"log","message":
                "function-level authorization was not tested: the unauthenticated client could not \
                 be built, and this probe has nothing to say without one. Nothing was run, so this \
                 is not a clean result."
            }));
        } else if params.auth.as_ref().is_some_and(|a| a.is_meaningful()) {
            // Narrowing the question is fine. Letting the narrowed question read
            // as the whole answer is not.
            let _ = tx.send(json!({"type":"log","message":
                "a credential was supplied, and the privileged operations above were still called \
                 without it. What is reported is what an anonymous caller can reach. Whether the \
                 supplied identity holds more rights than it should is a different question, and \
                 answering it needs identities labelled with the role each one is meant to have, \
                 which this job does not carry. Treat privilege escalation between roles as \
                 untested here rather than absent."
            }));
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

/// Machine-readable refusals. Apollo, graphql-js and the server frameworks built
/// on them put a stable code in `extensions.code`, which is worth more than any
/// amount of reading the message, because it does not change with the wording,
/// the locale, or the framework's release notes.
static AUTH_CODE: &[&str] = &[
    "unauthenticated",
    "unauthorized",
    "forbidden",
    "permission_denied",
    "permissiondenied",
    "access_denied",
    "accessdenied",
    "insufficient_permissions",
    "insufficient_scope",
    "not_authorized",
    "auth_not_authenticated",
    "auth_not_authorized",
];

/// Refusal wordings. This list is a convenience and not the boundary: it can only
/// ever hold the phrasings someone has already seen, so nothing that decides
/// whether to report a finding may depend on it alone.
static DENY_PHRASE: &[&str] = &[
    "unauthorized",
    "unauthorised",
    "forbidden",
    "not authorized",
    "not authorised",
    "must be logged in",
    "authentication required",
    "requires authentication",
    "permission denied",
    "do not have permission",
    "does not have permission",
    "no permission",
    "insufficient permission",
    "insufficient privileges",
    "not permitted",
    "access denied",
    "login required",
    "not allowed",
    "not accessible",
    "missing or invalid token",
    "invalid token",
    "token expired",
    "signature has expired",
];

/// Does this one error entry read as a refusal?
fn error_is_denial(e: &Value) -> bool {
    let code = e
        .pointer("/extensions/code")
        .and_then(|c| c.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if AUTH_CODE.contains(&code.as_str()) {
        return true;
    }
    let msg = e
        .get("message")
        .and_then(|m| m.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    DENY_PHRASE.iter().any(|p| msg.contains(p))
}

/// Is the server blaming this specific field for the error? Per the GraphQL spec a
/// field error carries the response `path` it occurred at, and a request error
/// (parse, validation, variable coercion) carries no `path` at all, because no
/// execution happened for it to have a path in. That distinction is structural,
/// so it is the one to test.
fn error_blames_field(e: &Value, field: &Field) -> bool {
    let Some(path) = e.get("path").and_then(|p| p.as_array()) else {
        return false;
    };
    // The path a namespaced operation errors at is ["system", "info", ...], so
    // the namespace has to match too. An error at `system.flags` says nothing
    // about whether `system.info` ran.
    let want: Vec<&str> = match &field.parent {
        Some(ns) => vec![ns.as_str(), field.name.as_str()],
        None => vec![field.name.as_str()],
    };
    if path.len() < want.len() {
        return false;
    }
    want.iter()
        .zip(path.iter())
        .all(|(w, got)| got.as_str() == Some(*w))
}

/// The GraphQL response denied the operation (authorization error), so it is NOT a BFLA hit.
fn denied(body: &str) -> bool {
    match serde_json::from_str::<Value>(body) {
        Ok(v) => v
            .get("errors")
            .and_then(|e| e.as_array())
            .map(|errs| errs.iter().any(error_is_denial))
            .unwrap_or(false),
        // Not JSON at all, so fall back to reading it. A WAF or a reverse proxy
        // can refuse in HTML before the GraphQL server ever sees the request.
        Err(_) => {
            let low = body.to_ascii_lowercase();
            DENY_PHRASE.iter().any(|p| low.contains(p))
        }
    }
}

/// The named resolver actually ran (returned data, or errored on something other than authorization -
/// e.g. a validation/type error means auth let the call THROUGH to the resolver).
fn resolver_ran(body: &str, field: &Field) -> bool {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return false;
    };
    let ptr = match &field.parent {
        Some(ns) => format!("/data/{ns}/{}", field.name),
        None => format!("/data/{}", field.name),
    };
    // The unambiguous case: the field answered.
    if v.pointer(&ptr).map(|d| !d.is_null()).unwrap_or(false) {
        return true;
    }
    // Otherwise the only thing that proves execution reached the resolver is an
    // error the server attributes to this field and does not describe as a
    // refusal.
    //
    // This used to accept any error the phrase list did not recognise, on the
    // reasoning that a validation or type error means authorization let the call
    // through to the resolver. In GraphQL that reasoning does not hold, because
    // validation is a phase that completes before execution begins: a validation
    // error is proof the resolver did NOT run. It also made the phrase list
    // load-bearing in the fail-open direction, so an API that refused in wording
    // nobody had written down yet was read as an API that had not refused.
    // Measured against six real refusal wordings and four validation errors, all
    // ten came back as `true`, which on any correctly secured GraphQL API is one
    // confirmed high-severity BFLA per privileged-looking field in the schema.
    v.get("errors")
        .and_then(|e| e.as_array())
        .map(|errs| {
            errs.iter()
                .any(|e| error_blames_field(e, field) && !error_is_denial(e))
        })
        .unwrap_or(false)
}

/// A `Field` standing for a bare root operation, for the tests and for anywhere
/// only the name is known.
#[cfg(test)]
fn root_field(name: &str) -> Field {
    Field {
        op: "query",
        name: name.to_string(),
        ret_type_name: None,
        parent: None,
        selection: None,
        has_args: false,
        string_args: Vec::new(),
        needs_selection: false,
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
            let (ret_kind, ret_name) = f.get("type").map(unwrap_type).unwrap_or_default();
            let needs_selection = matches!(ret_kind.as_str(), "OBJECT" | "INTERFACE" | "UNION");
            let has_args = f
                .get("args")
                .and_then(|a| a.as_array())
                .is_some_and(|a| !a.is_empty());
            out.push(Field {
                op,
                name: name.to_string(),
                ret_type_name: (!ret_name.is_empty()).then_some(ret_name),
                parent: None,
                // Filled in by `authz_probes`, which has the type index. Left
                // empty here so the injection phase keeps the document it has
                // always sent.
                selection: None,
                has_args,
                string_args,
                needs_selection,
            });
        }
    }
    out
}

/// Build a GraphQL document exercising `field` with `value` placed in `inj_arg` (other string args
/// get a benign filler so required args are satisfied).
/// The first field of this type that returns a scalar or an enum, which is the
/// only kind of selection that proves something was read.
///
/// Its absence is the other half of the rule. An object type with no scalar
/// anywhere in it is not data, it is a namespace: its fields are the operations.
/// `SystemQuery` in Wiki.js is `flags`, `info`, `extensions`, `exportStatus`,
/// and not one scalar among them.
fn scalar_leaf(t: &Value) -> Option<String> {
    let fields = t.get("fields")?.as_array()?;
    fields.iter().find_map(|f| {
        let name = f.get("name")?.as_str()?;
        if name.starts_with("__") {
            return None;
        }
        // A scalar behind arguments is not a free read, so it is no use as a
        // selection.
        if f.get("args")
            .and_then(|a| a.as_array())
            .is_some_and(|a| !a.is_empty())
        {
            return None;
        }
        let (kind, _) = f.get("type").map(unwrap_type).unwrap_or_default();
        matches!(kind.as_str(), "SCALAR" | "ENUM").then(|| name.to_string())
    })
}

/// The operations an authorization probe should actually call.
///
/// Two things were wrong with probing root fields directly, and both were found
/// by pointing the engine at Wiki.js 2.5.307, whose entire administrative API is
/// GraphQL. Of its 35 root fields exactly one matched the privileged-name
/// vocabulary, and that one was `system`, a namespace. So the engine produced one
/// false positive and examined none of the operations that actually check
/// anything.
///
/// A root field is an operation when it returns data, or when it takes arguments,
/// because a container has nothing to parameterise. Otherwise the operations are
/// one level inside it, and the privilege is carried by the namespace rather than
/// the leaf: `system { info }` is privileged because of `system`, while `info`
/// says nothing on its own. A privileged namespace therefore lends its privilege
/// to every leaf it contains.
///
/// Whatever is probed gets a real scalar selected out of it, because the earlier
/// `__typename` asked the server to name a type rather than to return anything.
/// Wiki.js authorizes the scalar leaves of `SystemInfo`, so `system { info {
/// __typename } }` answers an anonymous caller and `system { info { hostname } }`
/// does not: selecting `__typename` turned a correct refusal into a finding one
/// level deeper than the first one.
fn authz_probes(schema: &Value, roots: &[Field]) -> Vec<Field> {
    let empty = Vec::new();
    let types: &Vec<Value> = schema
        .pointer("/data/__schema/types")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty);
    let type_by_name = |want: &str| -> Option<&Value> {
        types
            .iter()
            .find(|t| t.get("name").and_then(|n| n.as_str()) == Some(want))
    };
    // What to select out of a field, given the type it returns.
    let selection_for = |ret: Option<&String>| -> Option<String> {
        ret.and_then(|n| type_by_name(n)).and_then(scalar_leaf)
    };

    let mut out = Vec::new();
    for r in roots {
        if !is_privileged_name(&r.name) {
            continue;
        }
        let ret = r.ret_type_name.as_ref().and_then(|n| type_by_name(n));
        // A scalar or enum return is data, always. Only an object can be a
        // namespace, and `needs_selection` is already the test for that: without
        // it, `debugConfig: String` looked up the `String` type, found it has no
        // fields and therefore no scalar leaf, and was classified as a namespace
        // with nothing in it. It was then dropped entirely, which took the
        // benchmark's positive control with it.
        let is_namespace =
            !r.has_args && r.needs_selection && ret.is_some_and(|t| scalar_leaf(t).is_none());
        if !is_namespace {
            let mut f = r.clone();
            f.selection = selection_for(r.ret_type_name.as_ref());
            out.push(f);
            continue;
        }
        let Some(leaves) = ret.and_then(|t| t.get("fields")).and_then(|f| f.as_array()) else {
            continue;
        };
        for leaf in leaves {
            let Some(name) = leaf.get("name").and_then(|v| v.as_str()) else {
                continue;
            };
            if name.starts_with("__") {
                continue;
            }
            let mut string_args = Vec::new();
            if let Some(args) = leaf.get("args").and_then(|v| v.as_array()) {
                for a in args {
                    let an = a.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    let (_k, tn) = a.get("type").map(unwrap_type).unwrap_or_default();
                    if !an.is_empty() && (tn == "String" || tn == "ID") {
                        string_args.push(an.to_string());
                    }
                }
            }
            let (kind, leaf_ret) = leaf.get("type").map(unwrap_type).unwrap_or_default();
            let leaf_ret = (!leaf_ret.is_empty()).then_some(leaf_ret);
            out.push(Field {
                op: r.op,
                name: name.to_string(),
                selection: selection_for(leaf_ret.as_ref()),
                ret_type_name: leaf_ret,
                parent: Some(r.name.clone()),
                has_args: leaf
                    .get("args")
                    .and_then(|a| a.as_array())
                    .is_some_and(|a| !a.is_empty()),
                string_args,
                needs_selection: matches!(kind.as_str(), "OBJECT" | "INTERFACE" | "UNION"),
            });
        }
    }
    // A namespace can be wide, and this probe sends one request per operation as
    // an unauthenticated caller. Enough to be useful, bounded enough not to look
    // like a flood.
    out.truncate(120);
    out
}

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
    let sel = match (field.needs_selection, field.selection.as_deref()) {
        (true, Some(leaf)) => format!(" {{ {leaf} }}"),
        (true, None) => " { __typename }".to_string(),
        (false, _) => String::new(),
    };
    let op_kw = if field.op == "mutation" {
        "mutation"
    } else {
        "query"
    };
    let body = match &field.parent {
        Some(ns) => format!("{ns} {{ {call}{sel} }}"),
        None => format!("{call}{sel}"),
    };
    json!({ "query": format!("{op_kw} {{ {body} }}") }).to_string()
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
            let pl = format!("1{sep}{} http://{host}/g{close}", crate::inject::OOB_CURL);
            let _ = post(client, url, &build_doc(field, arg, &pl)).await;
            let pl2 = format!("1{sep}{} {host}{close}", crate::inject::OOB_NSLOOKUP);
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
            ret_type_name: None,
            parent: None,
            selection: None,
            has_args: false,
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

    /// A job with no usable endpoint must refuse, not finish quietly. This ran
    /// to completion and reported `found: 0` against the URL `/graphql`, which
    /// is the same wire output as a GraphQL API with nothing wrong with it.
    #[tokio::test]
    async fn a_job_with_no_endpoint_refuses_instead_of_reporting_clean() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        run(
            GraphqlParams {
                target: String::new(),
                endpoint: "/graphql".into(),
                timeout_ms: 12_000,
                evasive: false,
                identify: None,
                auth: None,
                oast: None,
                classes: vec![],
                test_writes: false,
                block_internal: false,
            },
            tx,
        )
        .await;

        let mut msgs = Vec::new();
        while let Ok(m) = rx.try_recv() {
            msgs.push(m);
        }
        let said = msgs.iter().any(|m| {
            m["type"] == "log"
                && m["message"]
                    .as_str()
                    .unwrap_or("")
                    .contains("not a clean result")
        });
        assert!(said, "must say the result is not clean: {msgs:?}");
        assert!(
            !msgs.iter().any(|m| m["type"] == "finding"),
            "nothing was reachable, so nothing can be found: {msgs:?}"
        );
    }

    /// Ten bodies that all read as "the resolver ran" before this was fixed. Four
    /// are validation errors, which in GraphQL happen before execution starts, so
    /// they prove the opposite. Six are real refusals from real APIs, whose
    /// wording the phrase list did not happen to contain.
    #[test]
    fn a_request_level_error_is_not_evidence_the_resolver_ran() {
        for body in [
            r#"{"errors":[{"message":"Field \"adminUsers\" argument \"first\" of type \"Int!\" is required but not provided.","locations":[{"line":1,"column":9}]}]}"#,
            r#"{"errors":[{"message":"Cannot query field \"adminSettings\" on type \"Query\". Did you mean \"settings\"?"}]}"#,
            r#"{"errors":[{"message":"Expected type \"RoleEnum\", found \"1\"."}]}"#,
            r#"{"errors":[{"message":"Syntax Error: Expected Name, found }"}]}"#,
        ] {
            assert!(
                !resolver_ran(body, &root_field("adminUsers")),
                "validation happens before execution: {body}"
            );
        }
    }

    #[test]
    fn a_refusal_is_recognised_however_it_is_worded() {
        for body in [
            r#"{"data":{"adminUsers":null},"errors":[{"message":"You do not have permission to perform this action.","path":["adminUsers"]}]}"#,
            r#"{"data":null,"errors":[{"message":"Resource not accessible by integration","path":["adminUsers"]}]}"#,
            r#"{"errors":[{"message":"Insufficient permissions","path":["adminUsers"]}]}"#,
            r#"{"errors":[{"message":"requires authentication","path":["adminUsers"]}]}"#,
            r#"{"errors":[{"message":"Missing or invalid token","path":["adminUsers"]}]}"#,
            r#"{"errors":[{"message":"Signature has expired","path":["adminUsers"]}]}"#,
        ] {
            assert!(
                !resolver_ran(body, &root_field("adminUsers")),
                "a refused call did not reach the resolver: {body}"
            );
        }
        // "Resource not accessible by integration" is in no phrase list anyone
        // would write from first principles, so the machine-readable code has to
        // carry the ones the prose misses.
        let by_code = r#"{"data":null,"errors":[{"message":"nope","path":["adminUsers"],"extensions":{"code":"FORBIDDEN"}}]}"#;
        assert!(denied(by_code), "extensions.code FORBIDDEN is a refusal");
        assert!(!resolver_ran(by_code, &root_field("adminUsers")));
    }

    #[test]
    fn a_field_that_answered_is_still_a_hit() {
        // The whole point of the probe. None of the tightening above may cost it.
        assert!(resolver_ran(
            r#"{"data":{"audits":[{"__typename":"AuditObject"}]}}"#,
            &root_field("audits")
        ));
        assert!(resolver_ran(
            r#"{"data":{"systemHealth":"System Load: 0.92\n"}}"#,
            &root_field("systemHealth")
        ));
        // A resolver that ran and then failed on its own account: the server
        // blames the field by path, and the reason is not a refusal.
        assert!(resolver_ran(
            r#"{"data":{"adminUsers":null},"errors":[{"message":"Database connection failed","path":["adminUsers"]}]}"#,
            &root_field("adminUsers")
        ));
        // Data for the field wins even alongside an unrelated error elsewhere.
        assert!(resolver_ran(
            r#"{"data":{"audits":[1]},"errors":[{"message":"whatever","path":["other"]}]}"#,
            &root_field("audits")
        ));
    }

    #[test]
    fn an_error_blaming_a_different_field_says_nothing_about_this_one() {
        assert!(!resolver_ran(
            r#"{"data":{"audits":null},"errors":[{"message":"Database connection failed","path":["pastes"]}]}"#,
            &root_field("audits")
        ));
    }

    /// The shape Wiki.js 2.5.307 actually returns: every operation lives inside a
    /// domain namespace, and `SystemQuery` has four fields and not one scalar.
    fn wikijs_schema() -> Value {
        json!({"data":{"__schema":{
            "queryType":{"name":"Query","fields":[
                {"name":"system","args":[],"type":{"kind":"OBJECT","name":"SystemQuery","ofType":null}},
                {"name":"pages","args":[],"type":{"kind":"OBJECT","name":"PageQuery","ofType":null}}
            ]},
            "mutationType":{"name":"Mutation","fields":[]},
            "types":[
                {"name":"SystemQuery","kind":"OBJECT","fields":[
                    {"name":"flags","args":[],"type":{"kind":"LIST","name":null,"ofType":{"kind":"OBJECT","name":"SystemFlag"}}},
                    {"name":"info","args":[],"type":{"kind":"OBJECT","name":"SystemInfo","ofType":null}},
                    {"name":"extensions","args":[],"type":{"kind":"LIST","name":null,"ofType":{"kind":"OBJECT","name":"SystemExtension"}}},
                    {"name":"exportStatus","args":[],"type":{"kind":"OBJECT","name":"SystemExportStatus","ofType":null}}
                ]},
                {"name":"SystemInfo","kind":"OBJECT","fields":[
                    {"name":"currentVersion","args":[],"type":{"kind":"SCALAR","name":"String","ofType":null}},
                    {"name":"hostname","args":[],"type":{"kind":"SCALAR","name":"String","ofType":null}}
                ]}
            ]
        }}})
    }

    #[test]
    fn a_namespace_is_walked_into_rather_than_reported() {
        let schema = wikijs_schema();
        let roots = parse_fields(&schema);
        let probes = authz_probes(&schema, &roots);
        let names: Vec<String> = probes.iter().map(|f| f.path_name()).collect();
        // `system` is the only privileged root, and it is a container, so the
        // operations are its four leaves and the container itself is not one.
        assert_eq!(
            names,
            vec![
                "system.flags",
                "system.info",
                "system.extensions",
                "system.exportStatus"
            ],
            "got {names:?}"
        );
        assert!(
            !names.iter().any(|n| n == "system"),
            "the container answers everybody and proves nothing"
        );
    }

    #[test]
    fn a_namespaced_probe_asks_for_the_right_document() {
        let schema = wikijs_schema();
        let roots = parse_fields(&schema);
        let probes = authz_probes(&schema, &roots);
        let info = probes.iter().find(|f| f.name == "info").expect("info");
        // A real scalar out of SystemInfo, not `__typename`. Wiki.js answers
        // `__typename` to anybody and refuses `hostname`, so the document that
        // asks for a type name cannot tell a refusal from a leak.
        assert_eq!(
            build_doc(info, "", "1"),
            r#"{"query":"query { system { info { currentVersion } } }"}"#
        );
        // The namespace's other leaves have no scalar to reach for, so they are
        // asked about directly and `__typename` is the honest fallback.
        let flags = probes.iter().find(|f| f.name == "flags").unwrap();
        assert_eq!(
            build_doc(flags, "", "1"),
            r#"{"query":"query { system { flags { __typename } } }"}"#
        );
    }

    #[test]
    fn a_scalar_returning_field_is_never_a_namespace() {
        // Every one of these returns a scalar. `String` has no `fields`, so a
        // namespace test that only asks "has this type a scalar leaf" says yes
        // to all of them and drops them.
        let schema = json!({"data":{"__schema":{
            "queryType":{"name":"Query","fields":[
                {"name":"debugConfig","args":[],"type":{"kind":"SCALAR","name":"String","ofType":null}},
                {"name":"systemHealth","args":[],"type":{"kind":"SCALAR","name":"String","ofType":null}},
                {"name":"systemUpdate","args":[],"type":{"kind":"SCALAR","name":"String","ofType":null}}
            ]},
            "mutationType":{"name":"Mutation","fields":[]},
            "types":[{"name":"String","kind":"SCALAR","fields":null}]
        }}});
        let roots = parse_fields(&schema);
        let probes = authz_probes(&schema, &roots);
        let names: Vec<String> = probes.iter().map(|f| f.path_name()).collect();
        assert_eq!(
            names,
            vec!["debugConfig", "systemHealth", "systemUpdate"],
            "got {names:?}"
        );
        // And they are asked about bare, with no selection set.
        for f in &probes {
            assert_eq!(
                build_doc(f, "", "1"),
                format!(r#"{{"query":"query {{ {} }}"}}"#, f.name)
            );
        }
    }

    #[test]
    fn a_field_with_arguments_is_an_operation_not_a_namespace() {
        // dvga's `createUser` returns a payload object wrapping the record it
        // made, which has no scalar of its own, so it looked exactly like a
        // namespace and was walked into as `createUser.user`. It takes three
        // arguments, and a container has nothing to parameterise.
        let schema = json!({"data":{"__schema":{
            "queryType":{"name":"Query","fields":[]},
            "mutationType":{"name":"Mutation","fields":[
                {"name":"createUser","args":[
                    {"name":"username","type":{"kind":"SCALAR","name":"String","ofType":null}},
                    {"name":"email","type":{"kind":"SCALAR","name":"String","ofType":null}},
                    {"name":"password","type":{"kind":"SCALAR","name":"String","ofType":null}}
                ],"type":{"kind":"OBJECT","name":"CreateUserResult","ofType":null}}
            ]},
            "types":[
                {"name":"CreateUserResult","kind":"OBJECT","fields":[
                    {"name":"user","args":[],"type":{"kind":"OBJECT","name":"UserObject","ofType":null}}
                ]},
                {"name":"UserObject","kind":"OBJECT","fields":[
                    {"name":"id","args":[],"type":{"kind":"SCALAR","name":"Int","ofType":null}}
                ]}
            ]
        }}});
        let roots = parse_fields(&schema);
        let probes = authz_probes(&schema, &roots);
        let names: Vec<String> = probes.iter().map(|f| f.path_name()).collect();
        assert_eq!(names, vec!["createUser"], "got {names:?}");
    }

    #[test]
    fn a_namespaced_refusal_is_attributed_to_the_right_operation() {
        let schema = wikijs_schema();
        let roots = parse_fields(&schema);
        let probes = authz_probes(&schema, &roots);
        let info = probes.iter().find(|f| f.name == "info").unwrap();
        let flags = probes.iter().find(|f| f.name == "flags").unwrap();

        // What Wiki.js answers an anonymous caller. The code is generic, so the
        // refusal is only readable as prose, which is why the phrase list is kept.
        let forbidden = r#"{"errors":[{"message":"Forbidden","path":["system","info"],"extensions":{"code":"INTERNAL_SERVER_ERROR"}}],"data":{"system":{"info":null}}}"#;
        assert!(denied(forbidden));
        assert!(!resolver_ran(forbidden, info));
        // And an error at a sibling says nothing about this operation.
        assert!(!resolver_ran(forbidden, flags));

        // The container answering is not the operation answering.
        let container_only = r#"{"data":{"system":{"__typename":"SystemQuery"}}}"#;
        assert!(!resolver_ran(container_only, info));

        // A leaf that really did answer.
        let leaked = r#"{"data":{"system":{"info":{"__typename":"SystemInfo"}}}}"#;
        assert!(resolver_ran(leaked, info));
    }

    #[test]
    fn a_root_field_that_returns_data_is_still_the_operation() {
        // The control target's shape: privileged roots returning lists of objects
        // and scalars, with no namespace anywhere. Walking must not change these.
        let schema = json!({"data":{"__schema":{
            "queryType":{"name":"Query","fields":[
                {"name":"adminUsers","args":[],"type":{"kind":"LIST","name":null,"ofType":{"kind":"OBJECT","name":"User"}}},
                {"name":"debugConfig","args":[],"type":{"kind":"SCALAR","name":"String","ofType":null}},
                {"name":"me","args":[],"type":{"kind":"OBJECT","name":"User","ofType":null}}
            ]},
            "mutationType":{"name":"Mutation","fields":[]},
            "types":[
                {"name":"User","kind":"OBJECT","fields":[
                    {"name":"id","args":[],"type":{"kind":"SCALAR","name":"String","ofType":null}},
                    {"name":"email","args":[],"type":{"kind":"SCALAR","name":"String","ofType":null}}
                ]}
            ]
        }}});
        let roots = parse_fields(&schema);
        let probes = authz_probes(&schema, &roots);
        let names: Vec<String> = probes.iter().map(|f| f.path_name()).collect();
        assert_eq!(names, vec!["adminUsers", "debugConfig"], "got {names:?}");
        assert!(probes.iter().all(|f| f.parent.is_none()));
    }
}

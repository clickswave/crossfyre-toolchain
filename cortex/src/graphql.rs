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
    /// Identities to compare, each a role plus resolved auth. Two or more makes
    /// object-level authorization testable: the question "can this caller read
    /// that caller's object" needs no vocabulary and no guess about intent,
    /// which is what every other check here has needed.
    #[serde(default, deserialize_with = "de_null_seq")]
    pub identities: Vec<crate::authz::Identity>,
    /// introspection | suggestions | dos | batching | sensitive | authz | bola | injection ; empty/null = all.
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

const INTROSPECT: &str = r#"{"query":"{ __schema { queryType { name fields { name args { name type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } } type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } } } mutationType { name fields { name args { name type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } } type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } } } types { name kind fields { name args { name type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } } type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } } } } }"}"#;

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
    /// Further scalar leaves to fall back on, because the first one may not be
    /// readable for a reason that has nothing to do with authorization. Directus
    /// answers `settings { id }` with a pathless INTERNAL_SERVER_ERROR while
    /// `settings { project_name }` returns data, so a probe that committed to the
    /// first leaf read an unauthorized anonymous read as a refusal.
    alt_selections: Vec<String>,
    /// Whether the field returns a list of things rather than one thing.
    returns_list: bool,
    /// Whether the field takes any arguments at all. A field that takes
    /// arguments is an operation, never a namespace: a container has nothing to
    /// parameterise. Without this, a Relay-style mutation payload (an object
    /// wrapping the created record) looks exactly like a namespace, and dvga's
    /// `createUser(username, email, password)` was walked into as one.
    has_args: bool,
    string_args: Vec<String>,
    /// The subset of `string_args` the schema marks NON_NULL. Only these get a
    /// placeholder value. Filling an OPTIONAL argument invents a value the server
    /// then has to interpret, and Directus answers
    /// `settings(version: "1")` with `FORBIDDEN`, because it goes looking for
    /// version "1" in a collection an anonymous caller cannot read. The probe
    /// read that as the target refusing, when it was the target refusing the
    /// probe's own made-up argument, and the real finding underneath it was lost.
    req_args: Vec<String>,
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
        // Operations that answered without either refusing or returning
        // anything, on every selection tried. Named rather than dropped, for the
        // reason zero coverage is never reported as zero findings.
        let mut inconclusive: Vec<String> = Vec::new();
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
            let name = f.path_name();

            // Ask with each candidate selection until one of them settles the
            // question. A selection that cannot be read tells us nothing about
            // authorization, and treating it as a refusal is how a real
            // unauthorized read went unreported: Directus answers
            // `settings { id }` with a pathless INTERNAL_SERVER_ERROR and
            // `settings { project_name }` with the data.
            let mut probe = f.clone();
            let mut candidates: Vec<Option<String>> = Vec::new();
            if f.needs_selection {
                candidates.push(f.selection.clone());
                candidates.extend(f.alt_selections.iter().cloned().map(Some));
            } else {
                candidates.push(None);
            }

            let mut settled = false;
            for cand in candidates {
                probe.selection = cand;
                let Some(r) = post(anon, &url, &build_doc(&probe, "", "1")).await else {
                    // No response at all says nothing either way.
                    continue;
                };
                if r.status != 200 || denied(&r.body) {
                    // Refused, or refused before GraphQL saw it. Settled, and not
                    // a finding.
                    settled = true;
                    break;
                }
                if resolver_ran(&r.body, &probe) {
                    let _ = tx.send(finding(
                        "graphql_bfla",
                        "Privileged GraphQL operation reachable without authorization",
                        "high",
                        &url, "POST",
                        &format!("The privileged {} `{}` resolved for a caller sending no credential at all, with no authorization error. Function-level access control is missing on a sensitive operation (OWASP API5: BFLA) - anyone who can reach the endpoint can invoke admin/destructive functionality directly.", f.op, name),
                    ).param(&name).event());
                    found += 1;
                    settled = true;
                    break;
                }
                // Answered 200, refused nothing, returned nothing. Inconclusive:
                // try the next selection.
            }
            if !settled {
                inconclusive.push(name);
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
        if !inconclusive.is_empty() {
            inconclusive.sort();
            inconclusive.dedup();
            let _ = tx.send(json!({"type":"log","message": format!(
                "{} privileged operation(s) could not be settled either way: {}. Each answered 200 \
                 without refusing and without returning anything readable, on every field this \
                 probe knew how to ask for. Whether they are protected is untested here, not clean.",
                inconclusive.len(),
                inconclusive.join(", ")
            )}));
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

    // --- 6c. Object-level authorization (BOLA, API1) -------------------------------------------
    if want("bola") && !fields.is_empty() {
        let pairs = schema_json
            .as_ref()
            .map(|sj| object_pairs(sj, &fields))
            .unwrap_or_default();

        let named: Vec<&crate::authz::Identity> = params
            .identities
            .iter()
            .filter(|i| i.auth.is_meaningful())
            .collect();

        if named.len() < 2 {
            if !pairs.is_empty() {
                let _ = tx.send(json!({"type":"log","message": format!(
                    "object-level authorization was not tested. {} operation pair(s) that would \
                     support it were found, and the question needs at least two identities to \
                     compare: it is whether one caller can read another caller's object, and one \
                     caller cannot answer it. Untested here, not clean.",
                    pairs.len()
                )}));
            }
        } else {
            // A client per identity, all of them honest about who they are.
            let mut clients: Vec<(&str, Client)> = Vec::new();
            for id in &named {
                if let Some(c) = probe::build_client(probe::ClientOpts {
                    evasive: params.evasive,
                    identify: params.identify.clone(),
                    auth: Some(&id.auth),
                    target: &params.target,
                    timeout_ms: params.timeout_ms,
                    min_timeout_ms: 8000,
                    block_internal: params.block_internal,
                }) {
                    clients.push((id.role.as_str(), c));
                }
            }

            // The required arguments of a named mutation, already filled. Only
            // the required ones: a placeholder in an optional argument is a
            // value we invented and the server's answer to it is about us.
            let required_args = |name: &str, canary: &str| -> Vec<(String, String)> {
                schema_json
                    .as_ref()
                    .and_then(|sj| sj.pointer("/data/__schema/mutationType/fields"))
                    .and_then(|v| v.as_array())
                    .and_then(|a| {
                        a.iter()
                            .find(|m| m.get("name").and_then(|n| n.as_str()) == Some(name))
                    })
                    .map(|m| {
                        field_args(m)
                            .into_iter()
                            .filter(|(n, _, req)| *req && !id_shaped_arg(n))
                            .filter_map(|(n, t, _)| arg_literal(&t, canary).map(|v| (n, v)))
                            .collect()
                    })
                    .unwrap_or_default()
            };

            let mut examined = 0usize;
            // Operations where no disposable object could be made, so the write
            // side was not tested. Named rather than dropped.
            let mut no_throwaway: Vec<String> = Vec::new();
            for p in &pairs {
                // What each identity can enumerate for itself.
                let mut owned: Vec<(usize, Vec<Value>)> = Vec::new();
                for (i, (_role, c)) in clients.iter().enumerate() {
                    owned.push((i, ids_for(c, &url, p).await));
                }
                if owned.iter().all(|(_, ids)| ids.is_empty()) {
                    continue;
                }

                for (oi, ids) in &owned {
                    for id in ids {
                        // Exclusive to this identity: nobody else's list has it.
                        // Two identities that can both enumerate an object are
                        // not evidence of anything, which is the lesson of
                        // shared org-scoped resources.
                        let exclusive = owned
                            .iter()
                            .all(|(j, other)| j == oi || !other.contains(id));
                        if !exclusive {
                            continue;
                        }

                        let (_orole, oclient) = &clients[*oi];
                        let Some(a) = post(oclient, &url, &fetch_doc(p, id)).await else {
                            continue;
                        };
                        let Ok(av) = serde_json::from_str::<Value>(&a.body) else {
                            continue;
                        };
                        let ptr = fetch_ptr(p);
                        let Some(owner_obj) = av.pointer(&ptr).filter(|d| !d.is_null()).cloned()
                        else {
                            continue; // the owner cannot read it either
                        };
                        // Second read by the same identity, to learn which fields
                        // move on their own.
                        let volatile = match post(oclient, &url, &fetch_doc(p, id)).await {
                            Some(b) => serde_json::from_str::<Value>(&b.body)
                                .ok()
                                .and_then(|bv| bv.pointer(&ptr).cloned())
                                .map(|bo| volatile_keys(&owner_obj, &bo))
                                .unwrap_or_default(),
                            None => Vec::new(),
                        };
                        examined += 1;

                        for (pi, (prole, pclient)) in clients.iter().enumerate() {
                            if pi == *oi {
                                continue;
                            }
                            let Some(r) = post(pclient, &url, &fetch_doc(p, id)).await else {
                                continue;
                            };
                            if r.status != 200 || denied(&r.body) {
                                continue;
                            }
                            let Ok(rv) = serde_json::from_str::<Value>(&r.body) else {
                                continue;
                            };
                            let Some(peer_obj) = rv.pointer(&ptr).filter(|d| !d.is_null()) else {
                                continue;
                            };
                            if !same_object(&owner_obj, peer_obj, &volatile) {
                                continue;
                            }
                            let owner_role = clients[*oi].0;
                            let path = p.fetch.path_name();
                            let _ = tx.send(finding(
                                "graphql_bola",
                                "GraphQL object readable by an identity that does not own it",
                                "critical",
                                &url, "POST",
                                &format!(
                                    "`{path}({}: {id})` returned the same object to `{prole}` as it did to `{owner_role}`, and only `{owner_role}` can enumerate that object. Object-level authorization is missing (OWASP API1: BOLA): the id is the only thing standing between one account and another account's data.",
                                    p.id_arg
                                ),
                            ).param(&format!("{path}({})", p.id_arg)).event());
                            found += 1;
                        }
                    }
                }
            }
            // --- write side, opt-in ------------------------------------------
            //
            // Safe by construction, and the construction is the whole argument:
            // the only object this ever writes to is one it created itself, in
            // this run, for this purpose. A pre-existing object is never
            // addressed, so there is nothing of the customer's to lose. Where a
            // throwaway cannot be made, the probe says so and stops rather than
            // reaching for something real, which is the lesson of the matrix
            // that ignored `test_writes` and destroyed objects.
            if params.test_writes {
                for p in &pairs {
                    let Some(create) = p.create.as_ref() else {
                        no_throwaway.push(p.fetch.path_name());
                        continue;
                    };
                    if p.update.is_none() && p.remove.is_none() {
                        continue;
                    }
                    let (owner_role, oclient) = &clients[0];
                    let peers: Vec<&(&str, Client)> = clients.iter().skip(1).collect();
                    if peers.is_empty() {
                        continue;
                    }

                    // The owner makes something disposable.
                    let canary = format!("cfx-{}", rand_token());
                    // Find the new object by asking the owner what it has,
                    // before and after. Reading the id out of the mutation's own
                    // answer would mean knowing where in the payload it put the
                    // object, and a wrapper like `PageResponse { responseResult,
                    // page }` is the norm rather than the exception. The list is
                    // already known to work, because the read side used it.
                    let before_ids = ids_for(oclient, &url, p).await;
                    let cdoc = mutation_doc(
                        create,
                        &required_args(&create.name, &canary),
                        &[mutation_ack_field(create, schema_json.as_ref())],
                    );
                    let _ = post(oclient, &url, &cdoc).await;
                    let after_ids = ids_for(oclient, &url, p).await;
                    let fresh: Vec<&Value> = after_ids
                        .iter()
                        .filter(|id| !before_ids.contains(id))
                        .collect();
                    // Exactly one, or we do not know which object is ours, and
                    // writing to an object we are not certain we made is the one
                    // thing this probe must never do.
                    let Some(throwaway) = (fresh.len() == 1).then(|| fresh[0].clone()) else {
                        no_throwaway.push(p.fetch.path_name());
                        continue;
                    };

                    // It has to be readable by its owner, or nothing below can
                    // be told apart from the object never having existed.
                    let ptr = fetch_ptr(p);
                    let before = post(oclient, &url, &fetch_doc(p, &throwaway))
                        .await
                        .and_then(|r| serde_json::from_str::<Value>(&r.body).ok())
                        .and_then(|v| v.pointer(&ptr).cloned())
                        .filter(|d| !d.is_null());
                    if before.is_none() {
                        no_throwaway.push(p.fetch.path_name());
                        continue;
                    }

                    let mut destroyed = false;
                    for (prole, pclient) in &peers {
                        // Rewrite it as somebody else.
                        if let Some(upd) = p.update.as_ref() {
                            let mark = format!("cfx-{}", rand_token());
                            let mut args = vec![(
                                upd.string_args
                                    .iter()
                                    .find(|n| id_shaped_arg(n))
                                    .cloned()
                                    .unwrap_or_else(|| "id".into()),
                                throwaway.to_string(),
                            )];
                            if let Some(target) =
                                upd.string_args.iter().find(|n| !id_shaped_arg(n)).cloned()
                            {
                                args.push((target.clone(), json!(mark).to_string()));
                                let doc = mutation_doc(upd, &args, &[p.list_id_field.clone()]);
                                let _ = post(pclient, &url, &doc).await;
                                // The owner is the one who says whether it changed.
                                let after = post(oclient, &url, &fetch_doc(p, &throwaway))
                                    .await
                                    .and_then(|r| serde_json::from_str::<Value>(&r.body).ok())
                                    .and_then(|v| v.pointer(&ptr).cloned());
                                let changed =
                                    after.as_ref().and_then(|o| o.as_object()).is_some_and(|o| {
                                        o.values().any(|v| v.as_str() == Some(mark.as_str()))
                                    });
                                if changed {
                                    let name = upd.name.clone();
                                    let _ = tx.send(finding(
                                        "graphql_bola_write",
                                        "GraphQL object writable by an identity that does not own it",
                                        "critical",
                                        &url, "POST",
                                        &format!("`{name}({target}: ...)` let `{prole}` rewrite an object created by `{owner_role}`, and the change was confirmed by reading it back as its owner. Object-level authorization is missing on the write path (OWASP API1): the id is the only thing between one account and editing another account's data."),
                                    ).param(&format!("{name}({})", target)).event());
                                    found += 1;
                                }
                            }
                        }

                        // Destroy it as somebody else.
                        if let Some(del) = p.remove.as_ref() {
                            let idarg = del
                                .string_args
                                .iter()
                                .find(|n| id_shaped_arg(n))
                                .cloned()
                                .unwrap_or_else(|| "id".into());
                            let doc = mutation_doc(
                                del,
                                &[(idarg, throwaway.to_string())],
                                &[p.list_id_field.clone()],
                            );
                            let _ = post(pclient, &url, &doc).await;
                            let still = post(oclient, &url, &fetch_doc(p, &throwaway))
                                .await
                                .and_then(|r| serde_json::from_str::<Value>(&r.body).ok())
                                .and_then(|v| v.pointer(&ptr).cloned())
                                .filter(|d| !d.is_null());
                            if still.is_none() {
                                destroyed = true;
                                let name = del.name.clone();
                                let _ = tx.send(finding(
                                    "graphql_bola_delete",
                                    "GraphQL object deletable by an identity that does not own it",
                                    "critical",
                                    &url, "POST",
                                    &format!("`{name}` let `{prole}` destroy an object created by `{owner_role}`, and its absence was confirmed by reading it back as its owner. Object-level authorization is missing on the delete path (OWASP API1). This probe only ever addressed an object it created for the purpose, so nothing of yours was lost proving it."),
                                ).param(&name).event());
                                found += 1;
                                break;
                            }
                        }
                    }

                    // Tidy up after ourselves, unless a peer already did.
                    if !destroyed {
                        if let Some(del) = p.remove.as_ref() {
                            let idarg = del
                                .string_args
                                .iter()
                                .find(|n| id_shaped_arg(n))
                                .cloned()
                                .unwrap_or_else(|| "id".into());
                            let doc = mutation_doc(
                                del,
                                &[(idarg, throwaway.to_string())],
                                &[p.list_id_field.clone()],
                            );
                            let _ = post(oclient, &url, &doc).await;
                        }
                    }
                }
            }

            if !no_throwaway.is_empty() {
                no_throwaway.sort();
                no_throwaway.dedup();
                let _ = tx.send(json!({"type":"log","message": format!(
                    "the write side of object-level authorization was not tested on {}: no \
                     disposable object could be created for it, and this probe never addresses \
                     an object it did not make. Untested there, not clean.",
                    no_throwaway.join(", ")
                )}));
            }
            if examined == 0 {
                let _ = tx.send(json!({"type":"log","message": format!(
                    "object-level authorization found nothing to compare. {} operation pair(s) \
                     looked usable, and no identity could enumerate an object that the others \
                     could not, so there was no owner to impersonate. Untested here, not clean.",
                    pairs.len()
                )}));
            }
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
        alt_selections: Vec::new(),
        req_args: Vec::new(),
        returns_list: false,
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

/// Does this type ref contain a LIST anywhere in its wrappers? The other thing
/// `unwrap_type` throws away, and the id source for an object-level test has to
/// be a list: `pages.version` returns one object and would yield no ids at all,
/// while looking exactly like a candidate once the wrappers are gone.
fn type_is_list(t: &Value) -> bool {
    let mut cur = t;
    for _ in 0..8 {
        if cur.get("kind").and_then(|k| k.as_str()) == Some("LIST") {
            return true;
        }
        match cur.get("ofType") {
            Some(inner) if !inner.is_null() => cur = inner,
            _ => return false,
        }
    }
    false
}

/// Is this argument required? NON_NULL at the top of the type ref, which is the
/// one thing `unwrap_type` deliberately throws away.
fn arg_is_required(t: &Value) -> bool {
    t.get("kind").and_then(|k| k.as_str()) == Some("NON_NULL")
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
            let mut req_args = Vec::new();
            if let Some(args) = f.get("args").and_then(|v| v.as_array()) {
                for a in args {
                    let an = a.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    let (_k, tn) = a.get("type").map(unwrap_type).unwrap_or_default();
                    if !an.is_empty() && (tn == "String" || tn == "ID") {
                        string_args.push(an.to_string());
                        if a.get("type").is_some_and(arg_is_required) {
                            req_args.push(an.to_string());
                        }
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
                alt_selections: Vec::new(),
                req_args,
                returns_list: f.get("type").is_some_and(type_is_list),
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
    scalar_leaves(t).into_iter().next()
}

/// Every freely readable scalar or enum field of this type, in schema order,
/// capped at a few. More than one is needed because the first is not always
/// readable: it is very often `id`, and `id` is the field most likely to be
/// special-cased, computed, or to blow up on a singleton.
fn scalar_leaves(t: &Value) -> Vec<String> {
    let Some(fields) = t.get("fields").and_then(|f| f.as_array()) else {
        return Vec::new();
    };
    fields
        .iter()
        .filter_map(|f| {
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
        .take(4)
        .collect()
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
    let selections_for = |ret: Option<&String>| -> Vec<String> {
        ret.and_then(|n| type_by_name(n))
            .map(scalar_leaves)
            .unwrap_or_default()
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
            let mut cands = selections_for(r.ret_type_name.as_ref());
            f.selection = (!cands.is_empty()).then(|| cands.remove(0));
            f.alt_selections = cands;
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
            let mut req_args = Vec::new();
            if let Some(args) = leaf.get("args").and_then(|v| v.as_array()) {
                for a in args {
                    let an = a.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    let (_k, tn) = a.get("type").map(unwrap_type).unwrap_or_default();
                    if !an.is_empty() && (tn == "String" || tn == "ID") {
                        string_args.push(an.to_string());
                        if a.get("type").is_some_and(arg_is_required) {
                            req_args.push(an.to_string());
                        }
                    }
                }
            }
            let (kind, leaf_ret) = leaf.get("type").map(unwrap_type).unwrap_or_default();
            let leaf_ret = (!leaf_ret.is_empty()).then_some(leaf_ret);
            let mut cands = selections_for(leaf_ret.as_ref());
            let first = (!cands.is_empty()).then(|| cands.remove(0));
            out.push(Field {
                op: r.op,
                name: name.to_string(),
                selection: first,
                alt_selections: cands,
                ret_type_name: leaf_ret,
                parent: Some(r.name.clone()),
                req_args,
                returns_list: leaf.get("type").is_some_and(type_is_list),
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
        // The argument under test always goes in. Everything else goes in only
        // if the schema requires it: a placeholder in an optional argument is a
        // value we invented, and the server's answer to it is about us.
        .filter(|a| *a == inj_arg || field.req_args.contains(a))
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

// --- Object-level authorization (BOLA, API1) -------------------------------------------------
//
// Every other check in this engine has needed a guess about intent. The
// privileged-name vocabulary is a guess, and it is now the binding limit: of
// Wiki.js's 35 root namespaces exactly one matched it, so the engine examined
// four operations and said nothing about the rest.
//
// This question needs no guess. Given two callers of the same standing, can one
// of them read an object that belongs to the other? Nothing about the schema has
// to be interpreted, because the comparison is between two identities the caller
// supplied and told us are separate people.

/// Does this argument name an object reference?
fn id_shaped_arg(name: &str) -> bool {
    let low = name.to_ascii_lowercase();
    low == "id" || low.ends_with("id") && low.len() <= 24
}

/// The scalar field on a type that carries its identity.
fn id_field_of(t: &Value) -> Option<String> {
    let fields = t.get("fields")?.as_array()?;
    let named = |want: &str| {
        fields.iter().find_map(|f| {
            let n = f.get("name")?.as_str()?;
            (n.eq_ignore_ascii_case(want)).then(|| n.to_string())
        })
    };
    named("id").or_else(|| {
        fields.iter().find_map(|f| {
            let n = f.get("name")?.as_str()?;
            let (kind, _) = f.get("type").map(unwrap_type).unwrap_or_default();
            (id_shaped_arg(n) && matches!(kind.as_str(), "SCALAR" | "ENUM")).then(|| n.to_string())
        })
    })
}

/// One operation that lists objects and one that fetches a single object by id.
/// They routinely return DIFFERENT types: Wiki.js lists `PageListItem` and
/// fetches `Page`, so pairing them by return type would find nothing.
struct ObjectPair {
    list: Field,
    fetch: Field,
    id_arg: String,
    list_id_field: String,
    fetch_selection: Vec<String>,
    /// Mutations that address the same type, for the write side. Reading
    /// somebody else's invoice is bad; rewriting or destroying it is worse, and
    /// the REST engine's numbers put delete-by-id at the top of the yield.
    create: Option<Field>,
    update: Option<Field>,
    remove: Option<Field>,
}

fn object_pairs(schema: &Value, roots: &[Field]) -> Vec<ObjectPair> {
    let empty = Vec::new();
    let types: &Vec<Value> = schema
        .pointer("/data/__schema/types")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty);
    let by_name = |want: &str| -> Option<&Value> {
        types
            .iter()
            .find(|t| t.get("name").and_then(|n| n.as_str()) == Some(want))
    };

    // Everything callable, root fields and one level into each namespace, since
    // `pages.single` is inside `pages` and that is where real APIs keep it.
    //
    // The arguments are read from the schema here rather than taken from
    // `roots`, whose `string_args` holds only String and ID because that is what
    // the injection phase needs. An object reference is an `Int` as often as
    // not, so a root field like `invoice(id: Int)` was invisible: the pairs were
    // found inside namespaces, where this function had always built its own arg
    // list, and missed at the root of every flat schema.
    let arg_names = |f: &Value| -> (Vec<String>, Vec<String>) {
        let mut all = Vec::new();
        let mut req = Vec::new();
        if let Some(args) = f.get("args").and_then(|v| v.as_array()) {
            for a in args {
                let an = a.get("name").and_then(|v| v.as_str()).unwrap_or("");
                if an.is_empty() {
                    continue;
                }
                all.push(an.to_string());
                if a.get("type").is_some_and(arg_is_required) {
                    req.push(an.to_string());
                }
            }
        }
        (all, req)
    };
    let root_defs: Vec<&Value> = schema
        .pointer("/data/__schema/queryType/fields")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    let def_for = |name: &str| -> Option<&Value> {
        root_defs
            .iter()
            .copied()
            .find(|f| f.get("name").and_then(|n| n.as_str()) == Some(name))
    };

    let mut ops: Vec<Field> = Vec::new();
    for r in roots {
        if r.op != "query" {
            continue;
        }
        let mut root = r.clone();
        if let Some(def) = def_for(&r.name) {
            let (all, req) = arg_names(def);
            root.string_args = all;
            root.req_args = req;
        }
        ops.push(root);
        let Some(t) = r.ret_type_name.as_ref().and_then(|n| by_name(n)) else {
            continue;
        };
        if r.has_args || scalar_leaf(t).is_some() {
            continue; // returns data, so it is an operation and not a namespace
        }
        let Some(leaves) = t.get("fields").and_then(|f| f.as_array()) else {
            continue;
        };
        for leaf in leaves {
            let Some(name) = leaf.get("name").and_then(|v| v.as_str()) else {
                continue;
            };
            if name.starts_with("__") {
                continue;
            }
            let (kind, ret) = leaf.get("type").map(unwrap_type).unwrap_or_default();
            let mut args = Vec::new();
            let mut req = Vec::new();
            if let Some(a) = leaf.get("args").and_then(|v| v.as_array()) {
                for arg in a {
                    let an = arg.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    if an.is_empty() {
                        continue;
                    }
                    args.push(an.to_string());
                    if arg.get("type").is_some_and(arg_is_required) {
                        req.push(an.to_string());
                    }
                }
            }
            ops.push(Field {
                op: "query",
                name: name.to_string(),
                ret_type_name: (!ret.is_empty()).then_some(ret),
                parent: Some(r.name.clone()),
                selection: None,
                alt_selections: Vec::new(),
                req_args: req,
                returns_list: leaf.get("type").is_some_and(type_is_list),
                has_args: !args.is_empty(),
                string_args: args,
                needs_selection: matches!(kind.as_str(), "OBJECT" | "INTERFACE" | "UNION"),
            });
        }
    }

    // A list is any object-returning field with no REQUIRED argument whose item
    // type carries an id. A fetch is any object-returning field whose only
    // argument is an object reference.
    let mut out = Vec::new();
    for fetch in &ops {
        // One object, addressed by one reference. A list is not a fetch.
        if fetch.string_args.len() != 1 || !fetch.needs_selection || fetch.returns_list {
            continue;
        }
        let id_arg = fetch.string_args[0].clone();
        if !id_shaped_arg(&id_arg) {
            continue;
        }
        let Some(fetch_t) = fetch.ret_type_name.as_ref().and_then(|n| by_name(n)) else {
            continue;
        };
        let sel = scalar_leaves(fetch_t);
        if sel.is_empty() {
            continue;
        }
        // Which list enumerates the objects this fetch addresses. Taking the
        // first candidate in the namespace is not good enough: at the root of a
        // flat schema that is whatever happens to be declared earliest, so
        // `invoice(id)` was paired with `adminUsers` and handed ids that address
        // nothing. Score instead, and take the best.
        let list = ops
            .iter()
            .enumerate()
            .filter(|(_, l)| {
                l.parent == fetch.parent
                    && l.name != fetch.name
                    && l.needs_selection
                    && l.returns_list
                    && l.req_args.is_empty()
                    && l.ret_type_name
                        .as_ref()
                        .and_then(|n| by_name(n))
                        .and_then(id_field_of)
                        .is_some()
            })
            // Earliest wins a tie, because `max_by_key` keeps the LAST maximum
            // and every plain sibling scores the same. Without the Reverse,
            // `pages.single` paired with `pages.tags` rather than `pages.list`,
            // and tag ids address no page at all.
            .max_by_key(|(i, l)| {
                let score = if l.ret_type_name == fetch.ret_type_name {
                    // Returning the same type is the strongest evidence that
                    // these two operations are about the same objects.
                    3
                } else {
                    // Then the naming convention: `invoices` enumerates
                    // `invoice`.
                    let (ln, fname) =
                        (l.name.to_ascii_lowercase(), fetch.name.to_ascii_lowercase());
                    if ln == format!("{fname}s")
                        || ln == format!("{fname}es")
                        || fname == format!("{ln}s")
                    {
                        2
                    } else {
                        // Otherwise it is only a sibling, which is what pairs
                        // `pages.list` with `pages.single`: different types,
                        // unrelated names, and still the right answer.
                        1
                    }
                };
                (score, std::cmp::Reverse(*i))
            })
            .map(|(_, l)| l);
        let Some(list) = list else { continue };
        let list_id_field = list
            .ret_type_name
            .as_ref()
            .and_then(|n| by_name(n))
            .and_then(id_field_of)
            .expect("checked above");
        // Mutations addressing the same type. Matched on the return type first,
        // because that is the fact rather than the convention, with the verb in
        // the name as the second condition so `notes` does not look like a way
        // to create one.
        // Root mutations, plus one level into each mutation namespace, because
        // `pages.create` is inside `pages` exactly as `pages.single` is.
        let mut muts: Vec<(Option<String>, &Value)> = Vec::new();
        if let Some(roots) = schema
            .pointer("/data/__schema/mutationType/fields")
            .and_then(|v| v.as_array())
        {
            for m in roots {
                muts.push((None, m));
                let (_k, ret) = m.get("type").map(unwrap_type).unwrap_or_default();
                let Some(t) = (!ret.is_empty()).then_some(ret).and_then(|n| by_name(&n)) else {
                    continue;
                };
                let arg_count = m
                    .get("args")
                    .and_then(|a| a.as_array())
                    .map_or(0, |a| a.len());
                if arg_count > 0 || scalar_leaf(t).is_some() {
                    continue; // returns data, so it is an operation not a namespace
                }
                let Some(name) = m.get("name").and_then(|n| n.as_str()) else {
                    continue;
                };
                if let Some(leaves) = t.get("fields").and_then(|f| f.as_array()) {
                    for leaf in leaves {
                        muts.push((Some(name.to_string()), leaf));
                    }
                }
            }
        }
        // Matched on namespace, verb and whether it takes an object reference.
        // NOT on return type: a mutation almost always returns a payload wrapper
        // (`PageResponse { responseResult, page }`) rather than the object, so
        // requiring the types to match found nothing on real software.
        let find_mut = |verbs: &[&str], wants_id: bool| -> Option<Field> {
            let want_type = fetch
                .ret_type_name
                .clone()
                .unwrap_or_default()
                .to_ascii_lowercase();
            let want_name = fetch.name.to_ascii_lowercase();
            let usable: Vec<(usize, &(Option<String>, &Value))> = muts
                .iter()
                .enumerate()
                .filter(|(_, (ns, m))| {
                    let Some(name) = m.get("name").and_then(|n| n.as_str()) else {
                        return false;
                    };
                    let low = name.to_ascii_lowercase();
                    if !verbs.iter().any(|v| low.starts_with(v)) {
                        return false;
                    }
                    if ns.as_deref() != fetch.parent.as_deref() {
                        return false;
                    }
                    let args = field_args(m);
                    if args.iter().any(|(n, _, _)| id_shaped_arg(n)) != wants_id {
                        return false;
                    }
                    // Every required argument has to be one we can supply
                    // without inventing anything.
                    !args.iter().any(|(n, t, req)| {
                        *req && !id_shaped_arg(n) && arg_literal(t, "x").is_none()
                    })
                })
                .collect();
            // Is this mutation about the type we are testing? Requiring the
            // return type to match found nothing on real software, because a
            // payload wrapper is the norm. Dropping the requirement entirely was
            // worse: `invoice` then paired with `createNote`, the first create in
            // the namespace, and wrote to the wrong collection.
            let evidence = |m: &Value| -> i32 {
                let (_k, ret) = m.get("type").map(unwrap_type).unwrap_or_default();
                if !want_type.is_empty() && ret.to_ascii_lowercase() == want_type {
                    return 2;
                }
                let low = m
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if (!want_type.is_empty() && low.contains(&want_type))
                    || (!want_name.is_empty() && low.contains(&want_name))
                {
                    return 1;
                }
                0
            };
            let best = usable.iter().map(|(_, (_, m))| evidence(m)).max()?;
            // Nothing says this mutation is about this type, and there is more
            // than one it could be. Guessing writes to somebody else's
            // collection, so decline and say the write side was not tested.
            if best == 0 && usable.len() > 1 {
                return None;
            }
            usable
                .into_iter()
                .filter(|(_, (_, m))| evidence(m) == best)
                .min_by_key(|(i, _)| *i)
                .and_then(|(_, (ns, m))| {
                    let name = m.get("name")?.as_str()?;
                    let (kind, ret) = m.get("type").map(unwrap_type).unwrap_or_default();
                    let args = field_args(m);
                    Some(Field {
                        op: "mutation",
                        name: name.to_string(),
                        ret_type_name: (!ret.is_empty()).then_some(ret),
                        parent: ns.clone(),
                        selection: None,
                        alt_selections: Vec::new(),
                        req_args: args
                            .iter()
                            .filter(|(_, _, r)| *r)
                            .map(|(n, _, _)| n.clone())
                            .collect(),
                        returns_list: m.get("type").is_some_and(type_is_list),
                        has_args: !args.is_empty(),
                        string_args: args.iter().map(|(n, _, _)| n.clone()).collect(),
                        needs_selection: matches!(kind.as_str(), "OBJECT" | "INTERFACE" | "UNION"),
                    })
                })
        };
        out.push(ObjectPair {
            list: list.clone(),
            fetch: fetch.clone(),
            id_arg,
            list_id_field,
            fetch_selection: sel,
            create: find_mut(&["create", "add", "new"], false),
            update: find_mut(&["update", "edit", "modify", "patch"], true),
            remove: find_mut(&["delete", "remove", "destroy"], true),
        });
    }
    out.truncate(12);
    out
}

/// A short unique marker, so a value this probe wrote is recognisable as its own
/// and cannot be confused with anything the application produced.
fn rand_token() -> String {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:x}", n & 0xffff_ffff_ffff)
}

/// A literal for a required argument, chosen by its type. Returns None for
/// anything we would be guessing at: a custom scalar, an input object, an ID we
/// have no value for. Guessing produces a document the server has to interpret,
/// and its answer is then about us rather than about its authorization, which is
/// defect 26.
fn arg_literal(t: &Value, canary: &str) -> Option<String> {
    let (kind, name) = unwrap_type(t);
    if type_is_list(t) {
        return None;
    }
    match (kind.as_str(), name.as_str()) {
        ("SCALAR", "String") => Some(json!(canary).to_string()),
        ("SCALAR", "Int") => Some("1".into()),
        ("SCALAR", "Float") => Some("1.0".into()),
        ("SCALAR", "Boolean") => Some("false".into()),
        _ => None,
    }
}

/// Every argument of a field, with its type, in declaration order.
fn field_args(def: &Value) -> Vec<(String, Value, bool)> {
    def.get("args")
        .and_then(|a| a.as_array())
        .map(|args| {
            args.iter()
                .filter_map(|a| {
                    let n = a.get("name")?.as_str()?.to_string();
                    let t = a.get("type")?.clone();
                    let req = arg_is_required(&t);
                    Some((n, t, req))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// A mutation document, with only the arguments we were asked to supply.
fn mutation_doc(field: &Field, args: &[(String, String)], selection: &[String]) -> String {
    let arglist = args
        .iter()
        .map(|(k, v)| format!("{k}: {v}"))
        .collect::<Vec<_>>()
        .join(", ");
    let call = if arglist.is_empty() {
        field.name.clone()
    } else {
        format!("{}({arglist})", field.name)
    };
    let sel = if selection.is_empty() {
        String::new()
    } else {
        format!(" {{ {} }}", selection.join(" "))
    };
    let body = match &field.parent {
        Some(ns) => format!("{ns} {{ {call}{sel} }}"),
        None => format!("{call}{sel}"),
    };
    json!({ "query": format!("mutation {{ {body} }}") }).to_string()
}

/// Something valid to select out of a mutation's return type, without caring
/// what it is. A mutation answers with a payload wrapper as often as with the
/// object, so the safe request is any one of its own scalar fields, and
/// `__typename` when it has none.
fn mutation_ack_field(field: &Field, schema: Option<&Value>) -> String {
    let leaf = field
        .ret_type_name
        .as_ref()
        .and_then(|n| {
            schema?
                .pointer("/data/__schema/types")?
                .as_array()?
                .iter()
                .find(|t| t.get("name").and_then(|x| x.as_str()) == Some(n))
        })
        .and_then(scalar_leaf);
    leaf.unwrap_or_else(|| "__typename".to_string())
}

/// Where a mutation's answer lives in the response.
fn mutation_ptr(field: &Field) -> String {
    match &field.parent {
        Some(ns) => format!("/data/{ns}/{}", field.name),
        None => format!("/data/{}", field.name),
    }
}

/// `{ ns { field(arg: <raw>) { a b c } } }`, with the id emitted as the JSON
/// value it arrived as. It is very often an Int, and quoting it is a type error
/// rather than a finding.
fn fetch_doc(p: &ObjectPair, id: &Value) -> String {
    let sel = p.fetch_selection.join(" ");
    let call = format!("{}({}: {}) {{ {sel} }}", p.fetch.name, p.id_arg, id);
    let body = match &p.fetch.parent {
        Some(ns) => format!("{ns} {{ {call} }}"),
        None => call,
    };
    json!({ "query": format!("query {{ {body} }}") }).to_string()
}

fn list_doc(p: &ObjectPair) -> String {
    let call = format!("{} {{ {} }}", p.list.name, p.list_id_field);
    let body = match &p.list.parent {
        Some(ns) => format!("{ns} {{ {call} }}"),
        None => call,
    };
    json!({ "query": format!("query {{ {body} }}") }).to_string()
}

/// Where the answer to a fetch lives in the response.
fn fetch_ptr(p: &ObjectPair) -> String {
    match &p.fetch.parent {
        Some(ns) => format!("/data/{ns}/{}", p.fetch.name),
        None => format!("/data/{}", p.fetch.name),
    }
}

/// Ids this identity can enumerate for itself.
async fn ids_for(client: &Client, url: &str, p: &ObjectPair) -> Vec<Value> {
    let Some(r) = post(client, url, &list_doc(p)).await else {
        return Vec::new();
    };
    let Ok(v) = serde_json::from_str::<Value>(&r.body) else {
        return Vec::new();
    };
    let ptr = match &p.list.parent {
        Some(ns) => format!("/data/{ns}/{}", p.list.name),
        None => format!("/data/{}", p.list.name),
    };
    v.pointer(&ptr)
        .and_then(|d| d.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|it| it.get(&p.list_id_field).cloned())
                .filter(|id| !id.is_null())
                .take(25)
                .collect()
        })
        .unwrap_or_default()
}

/// Keys whose value changes between two reads by the SAME identity, so a
/// difference in them says nothing about who asked.
fn volatile_keys(a: &Value, b: &Value) -> Vec<String> {
    let (Some(a), Some(b)) = (a.as_object(), b.as_object()) else {
        return Vec::new();
    };
    a.keys()
        .filter(|k| a.get(*k) != b.get(*k))
        .cloned()
        .collect()
}

fn same_object(owner: &Value, peer: &Value, volatile: &[String]) -> bool {
    let (Some(o), Some(p)) = (owner.as_object(), peer.as_object()) else {
        return false;
    };
    let stable: Vec<&String> = o.keys().filter(|k| !volatile.contains(k)).collect();
    if stable.is_empty() {
        return false;
    }
    stable.iter().all(|k| o.get(*k) == p.get(*k))
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
            alt_selections: Vec::new(),
            has_args: false,
            op: "query",
            name: "paste".into(),
            string_args: vec!["id".into()],
            req_args: Vec::new(),
            returns_list: false,
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
                identities: vec![],
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
    fn an_optional_argument_is_left_out_rather_than_invented() {
        // Directus `settings(version: String)`. Filling it sent the server
        // looking for version "1" in a collection an anonymous caller cannot
        // read, which came back FORBIDDEN, and the probe read its own invented
        // argument as the target's authorization decision.
        let optional = Field {
            op: "query",
            name: "settings".into(),
            ret_type_name: Some("directus_settings".into()),
            parent: None,
            selection: Some("project_name".into()),
            alt_selections: Vec::new(),
            string_args: vec!["version".into()],
            req_args: Vec::new(),
            returns_list: false,
            has_args: true,
            needs_selection: true,
        };
        assert_eq!(
            build_doc(&optional, "", "1"),
            r#"{"query":"query { settings { project_name } }"}"#
        );

        // Required is different: leaving it out is an invalid document, which
        // proves nothing at all.
        let mut required = optional.clone();
        required.req_args = vec!["version".into()];
        let doc = build_doc(&required, "", "1");
        assert!(doc.contains("settings(version:"), "{doc}");
        assert!(doc.contains("project_name"), "{doc}");

        // And the argument being injected always goes in, optional or not,
        // because placing a payload in it is the entire point.
        assert!(build_doc(&optional, "version", "1' or '1").contains("version:"));
    }

    #[test]
    fn a_non_null_list_of_non_null_objects_resolves() {
        // Wiki.js types `pages.list` as NON_NULL<LIST<NON_NULL<PageListItem>>>,
        // which is four levels, and most code-generated schemas do the same. The
        // introspection query used to fetch two or three, so the innermost name
        // came back null: the field then read as returning a NON_NULL of nothing,
        // `needs_selection` was false, and the probe sent a document with no
        // selection set on an object type, which is invalid.
        let deep = json!({
            "kind":"NON_NULL","name":null,
            "ofType":{"kind":"LIST","name":null,
            "ofType":{"kind":"NON_NULL","name":null,
            "ofType":{"kind":"OBJECT","name":"PageListItem","ofType":null}}}
        });
        assert_eq!(
            unwrap_type(&deep),
            ("OBJECT".to_string(), "PageListItem".to_string())
        );

        let schema = json!({"data":{"__schema":{
            "queryType":{"name":"Query","fields":[
                {"name":"adminAudits","args":[],"type": deep}
            ]},
            "mutationType":{"name":"Mutation","fields":[]},
            "types":[
                {"name":"PageListItem","kind":"OBJECT","fields":[
                    {"name":"id","args":[],"type":{"kind":"SCALAR","name":"Int","ofType":null}},
                    {"name":"path","args":[],"type":{"kind":"SCALAR","name":"String","ofType":null}}
                ]}
            ]
        }}});
        let roots = parse_fields(&schema);
        assert!(roots[0].needs_selection, "an object list needs a selection");
        let probes = authz_probes(&schema, &roots);
        let doc = build_doc(&probes[0], "", "1");
        assert!(doc.contains("adminAudits { id }"), "{doc}");
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

    /// The Wiki.js page surface, which is the shape that matters: the list and
    /// the fetch return DIFFERENT types (`PageListItem` and `Page`), their names
    /// say nothing about each other, the id is an `Int`, and several siblings
    /// also return lists carrying an id.
    fn wikijs_pages_schema() -> Value {
        let pages_query =
            |name: &str, args: Value, ty: Value| json!({"name": name, "args": args, "type": ty});
        let list_of = |t: &str| {
            json!({
                "kind":"NON_NULL","name":null,
                "ofType":{"kind":"LIST","name":null,
                "ofType":{"kind":"NON_NULL","name":null,
                "ofType":{"kind":"OBJECT","name":t,"ofType":null}}}
            })
        };
        let int_arg =
            |n: &str| json!({"name": n, "type":{"kind":"SCALAR","name":"Int","ofType":null}});
        json!({"data":{"__schema":{
            "queryType":{"name":"Query","fields":[
                {"name":"pages","args":[],"type":{"kind":"OBJECT","name":"PageQuery","ofType":null}}
            ]},
            "mutationType":{"name":"Mutation","fields":[]},
            "types":[
                {"name":"PageQuery","kind":"OBJECT","fields":[
                    pages_query("history", json!([int_arg("id")]), json!({"kind":"OBJECT","name":"PageHistoryResult","ofType":null})),
                    pages_query("list", json!([int_arg("limit")]), list_of("PageListItem")),
                    pages_query("single", json!([int_arg("id")]), json!({"kind":"OBJECT","name":"Page","ofType":null})),
                    // A sibling that also returns a list with an id in it, and
                    // is declared AFTER `list`. Tag ids address no page.
                    pages_query("tags", json!([]), list_of("PageTag"))
                ]},
                {"name":"PageListItem","kind":"OBJECT","fields":[
                    {"name":"id","args":[],"type":{"kind":"SCALAR","name":"Int","ofType":null}},
                    {"name":"path","args":[],"type":{"kind":"SCALAR","name":"String","ofType":null}}
                ]},
                {"name":"PageTag","kind":"OBJECT","fields":[
                    {"name":"id","args":[],"type":{"kind":"SCALAR","name":"Int","ofType":null}},
                    {"name":"tag","args":[],"type":{"kind":"SCALAR","name":"String","ofType":null}}
                ]},
                {"name":"Page","kind":"OBJECT","fields":[
                    {"name":"id","args":[],"type":{"kind":"SCALAR","name":"Int","ofType":null}},
                    {"name":"path","args":[],"type":{"kind":"SCALAR","name":"String","ofType":null}},
                    {"name":"title","args":[],"type":{"kind":"SCALAR","name":"String","ofType":null}}
                ]},
                {"name":"PageHistoryResult","kind":"OBJECT","fields":[
                    {"name":"total","args":[],"type":{"kind":"SCALAR","name":"Int","ofType":null}}
                ]}
            ]
        }}})
    }

    #[test]
    fn the_list_that_enumerates_the_fetch_is_the_one_chosen() {
        let schema = wikijs_pages_schema();
        let roots = parse_fields(&schema);
        let pairs = object_pairs(&schema, &roots);
        let single = pairs
            .iter()
            .find(|p| p.fetch.name == "single")
            .expect("pages.single is a fetch");
        // `pages.tags` also returns a list with an id and is declared later.
        // Ties go to the earliest, because max_by_key keeps the LAST maximum and
        // without that the probe paired `single` with `tags` and asked for pages
        // by tag id.
        assert_eq!(single.list.name, "list", "paired with {}", single.list.name);
        assert_eq!(single.list_id_field, "id");
        assert_eq!(single.id_arg, "id");
        // The selection has to be real scalars off the FETCH's type, not the
        // list's.
        assert_eq!(single.fetch_selection, vec!["id", "path", "title"]);
    }

    #[test]
    fn an_int_id_is_not_quoted_and_a_namespace_is_kept() {
        let schema = wikijs_pages_schema();
        let roots = parse_fields(&schema);
        let pairs = object_pairs(&schema, &roots);
        let p = pairs.iter().find(|p| p.fetch.name == "single").unwrap();
        assert_eq!(
            fetch_doc(p, &json!(7)),
            r#"{"query":"query { pages { single(id: 7) { id path title } } }"}"#
        );
        // A string id keeps its quotes, because that is what the list handed us.
        assert!(fetch_doc(p, &json!("abc")).contains(r#"single(id: \"abc\")"#));
        assert_eq!(
            list_doc(p),
            r#"{"query":"query { pages { list { id } } }"}"#
        );
        assert_eq!(fetch_ptr(p), "/data/pages/single");
    }

    #[test]
    fn a_list_is_never_mistaken_for_a_fetch() {
        let schema = wikijs_pages_schema();
        let roots = parse_fields(&schema);
        let pairs = object_pairs(&schema, &roots);
        // `history(id)` takes one id-shaped arg but its type has no scalar
        // selection worth comparing, and `list(limit)` returns many things.
        for p in &pairs {
            assert!(!p.fetch.returns_list, "{} returns a list", p.fetch.name);
            assert!(p.list.returns_list, "{} is not a list", p.list.name);
        }
    }

    #[test]
    fn two_reads_that_differ_only_in_a_moving_field_are_the_same_object() {
        let first = json!({"id":1,"title":"Alpha","viewedAt":"10:00"});
        let again = json!({"id":1,"title":"Alpha","viewedAt":"10:01"});
        let vol = volatile_keys(&first, &again);
        assert_eq!(vol, vec!["viewedAt"]);
        // The peer got the same object, and only the moving field differs.
        let peer = json!({"id":1,"title":"Alpha","viewedAt":"10:02"});
        assert!(same_object(&first, &peer, &vol));
        // A genuinely different object is not the same one.
        let other = json!({"id":2,"title":"Beta","viewedAt":"10:02"});
        assert!(!same_object(&first, &other, &vol));
        // And if EVERY field moves there is nothing stable left to compare, so
        // no claim can be made.
        assert!(!same_object(
            &first,
            &peer,
            &["id".into(), "title".into(), "viewedAt".into()]
        ));
    }

    /// A flat schema with two owned collections and mutations for both, which is
    /// where the write side gets dangerous: pick the wrong create and the probe
    /// writes to a collection it is not testing and then fails to clean up after
    /// itself, because its delete is for the other one.
    fn two_collections_schema() -> Value {
        let obj = |n: &str| json!({"kind":"OBJECT","name":n,"ofType":null});
        let list = |n: &str| json!({"kind":"LIST","name":null,"ofType":obj(n)});
        let sarg =
            |n: &str| json!({"name":n,"type":{"kind":"SCALAR","name":"String","ofType":null}});
        let iarg = |n: &str| json!({"name":n,"type":{"kind":"SCALAR","name":"Int","ofType":null}});
        let fields = |n: &str| {
            json!([
                {"name":"id","args":[],"type":{"kind":"SCALAR","name":"Int","ofType":null}},
                {"name":n,"args":[],"type":{"kind":"SCALAR","name":"String","ofType":null}}
            ])
        };
        json!({"data":{"__schema":{
            "queryType":{"name":"Query","fields":[
                {"name":"notes","args":[],"type": list("Note")},
                {"name":"note","args":[iarg("id")],"type": obj("Note")},
                {"name":"invoices","args":[],"type": list("Invoice")},
                {"name":"invoice","args":[iarg("id")],"type": obj("Invoice")},
                // A collection with no mutations of its own at all.
                {"name":"announcements","args":[],"type": list("Announcement")},
                {"name":"announcement","args":[iarg("id")],"type": obj("Announcement")}
            ]},
            "mutationType":{"name":"Mutation","fields":[
                // Declared FIRST, so anything that takes the earliest candidate
                // picks this one for every collection.
                {"name":"createNote","args":[sarg("title")],"type": obj("Note")},
                {"name":"updateNote","args":[iarg("id"),sarg("title")],"type": obj("Note")},
                {"name":"deleteNote","args":[iarg("id")],"type": obj("Note")},
                {"name":"createInvoice","args":[sarg("reference")],"type": obj("Invoice")},
                {"name":"updateInvoice","args":[iarg("id"),sarg("reference")],"type": obj("Invoice")},
                {"name":"deleteInvoice","args":[iarg("id")],"type": obj("Invoice")}
            ]},
            "types":[
                {"name":"Note","kind":"OBJECT","fields": fields("title")},
                {"name":"Invoice","kind":"OBJECT","fields": fields("reference")},
                {"name":"Announcement","kind":"OBJECT","fields": fields("body")}
            ]
        }}})
    }

    #[test]
    fn a_mutation_is_matched_to_the_collection_it_is_actually_about() {
        let schema = two_collections_schema();
        let roots = parse_fields(&schema);
        let pairs = object_pairs(&schema, &roots);
        let get = |n: &str| {
            pairs
                .iter()
                .find(|p| p.fetch.name == n)
                .unwrap_or_else(|| panic!("no pair for {n}"))
        };

        let inv = get("invoice");
        assert_eq!(
            inv.create.as_ref().map(|f| f.name.as_str()),
            Some("createInvoice")
        );
        assert_eq!(
            inv.update.as_ref().map(|f| f.name.as_str()),
            Some("updateInvoice")
        );
        assert_eq!(
            inv.remove.as_ref().map(|f| f.name.as_str()),
            Some("deleteInvoice")
        );

        let note = get("note");
        assert_eq!(
            note.create.as_ref().map(|f| f.name.as_str()),
            Some("createNote")
        );
        assert_eq!(
            note.remove.as_ref().map(|f| f.name.as_str()),
            Some("deleteNote")
        );

        // Nothing in the schema says any mutation is about announcements, and
        // there is more than one it could be. Guessing writes to a collection we
        // are not testing, and then cleans up with the wrong delete and leaves
        // the object behind. Measured: that is exactly what happened, and it
        // left two notes in the target.
        let ann = get("announcement");
        assert!(
            ann.create.is_none(),
            "guessed {:?}",
            ann.create.as_ref().map(|f| &f.name)
        );
        assert!(
            ann.update.is_none(),
            "guessed {:?}",
            ann.update.as_ref().map(|f| &f.name)
        );
        assert!(
            ann.remove.is_none(),
            "guessed {:?}",
            ann.remove.as_ref().map(|f| &f.name)
        );
    }

    #[test]
    fn a_required_argument_we_cannot_supply_rules_the_mutation_out() {
        // Filling a required argument with something invented makes the server's
        // answer about us, so a create we cannot build honestly is no create at
        // all. A String we can do; a custom scalar or an input object we cannot.
        assert!(
            arg_literal(&json!({"kind":"SCALAR","name":"String","ofType":null}), "c").is_some()
        );
        assert!(arg_literal(&json!({"kind":"SCALAR","name":"Int","ofType":null}), "c").is_some());
        assert!(
            arg_literal(
                &json!({"kind":"SCALAR","name":"DateTime","ofType":null}),
                "c"
            )
            .is_none()
        );
        assert!(
            arg_literal(
                &json!({"kind":"INPUT_OBJECT","name":"NoteInput","ofType":null}),
                "c"
            )
            .is_none()
        );
        // A list of strings is still a guess about how many and which.
        assert!(
            arg_literal(
                &json!({"kind":"LIST","name":null,
                        "ofType":{"kind":"SCALAR","name":"String","ofType":null}}),
                "c"
            )
            .is_none()
        );
        // And NON_NULL<String> is a String.
        assert!(
            arg_literal(
                &json!({"kind":"NON_NULL","name":null,
                        "ofType":{"kind":"SCALAR","name":"String","ofType":null}}),
                "c"
            )
            .is_some()
        );
    }

    #[test]
    fn a_mutation_document_names_its_namespace_and_omits_what_it_was_not_given() {
        let schema = two_collections_schema();
        let roots = parse_fields(&schema);
        let pairs = object_pairs(&schema, &roots);
        let inv = pairs.iter().find(|p| p.fetch.name == "invoice").unwrap();
        let del = inv.remove.as_ref().unwrap();
        assert_eq!(
            mutation_doc(del, &[("id".into(), "7".into())], &["id".into()]),
            r#"{"query":"mutation { deleteInvoice(id: 7) { id } }"}"#
        );
        // No arguments at all is a valid mutation, and the optional ones stay out.
        let create = inv.create.as_ref().unwrap();
        assert_eq!(
            mutation_doc(create, &[], &["id".into()]),
            r#"{"query":"mutation { createInvoice { id } }"}"#
        );
    }
}

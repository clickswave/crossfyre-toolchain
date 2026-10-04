//! Parse an API description into a flat list of operations and their request shapes.
//!
//! Formats: OpenAPI 3.x and Swagger 2.0 (JSON or YAML), Postman collection v2.x, HAR, and
//! Insomnia v4. Each parser walks a `serde_json::Value`, YAML being deserialised into the
//! same representation, and produces operations; a malformed item is skipped rather than
//! failing the whole import, because one bad path in a two-hundred-path spec should not
//! cost the other hundred and ninety-nine.
//!
//! This is deliberately a parser and nothing else. It owns no storage, talks to no
//! database and knows nothing about what consumes it, which is what lets the desktop
//! application and the hosted platform share one implementation instead of two that
//! drift.
//!
//! ## Provenance is part of the output, not a detail
//!
//! A spec is a DECLARED contract and can disagree with the server that is actually
//! running. A HAR is CAPTURED traffic and is known to have worked. Treating those as the
//! same thing is how a tool ends up confidently reporting an endpoint that was removed
//! two releases ago, so the difference is carried on the result rather than inferred by
//! whoever reads it.

use serde_json::Value;
use std::collections::HashSet;

/// One parameter of a request, wherever it travels.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ImportedField {
    pub name: String,
    /// query | body | path | header | cookie
    pub location: String,
    pub ty: Option<String>,
    pub required: bool,
    pub enum_values: Vec<String>,
    pub format: Option<String>,
}

/// One operation, a method and a URL, plus whatever is known about its request shape.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ImportedOperation {
    pub method: String,
    pub url: String,
    pub content_type: Option<String>,
    pub auth_required: bool,
    pub summary: Option<String>,
    pub fields: Vec<ImportedField>,
}

pub struct ParseResult {
    pub operations: Vec<ImportedOperation>,
    /// "spec" (declared) or "observed" (captured concrete requests).
    pub source_label: &'static str,
    /// Whether the captured requests are known-good against the server.
    pub confirmed: bool,
    /// Human label of the detected format (for the UI).
    pub detected: String,
}

/// Parse `content` (JSON or YAML) as `format` ("auto" | "openapi" | "postman" | "har" |
/// "insomnia"). `base_url` supplies/overrides the target origin when the document's own servers are
/// relative or templated.
pub fn parse(content: &str, format: &str, base_url: Option<&str>) -> Result<ParseResult, String> {
    let doc = parse_doc(content)?;
    let base = base_url.map(|b| b.trim()).filter(|b| !b.is_empty());
    let fmt = if format.is_empty() || format == "auto" {
        detect(&doc).ok_or_else(|| {
            "could not detect the document format; pick one explicitly".to_string()
        })?
    } else {
        format.to_string()
    };
    match fmt.as_str() {
        "openapi" | "swagger" => parse_openapi(&doc, base),
        "postman" => parse_postman(&doc, base),
        "har" => parse_har(&doc),
        "insomnia" => parse_insomnia(&doc, base),
        other => Err(format!("unsupported format: {other}")),
    }
}

/// JSON first, then YAML (OpenAPI is frequently YAML). Both land in one `serde_json::Value`.
fn parse_doc(content: &str) -> Result<Value, String> {
    if let Ok(v) = serde_json::from_str::<Value>(content) {
        return Ok(v);
    }
    serde_yaml::from_str::<Value>(content).map_err(|e| format!("not valid JSON or YAML: {e}"))
}

fn detect(doc: &Value) -> Option<String> {
    if doc.get("openapi").is_some() || doc.get("swagger").is_some() {
        return Some("openapi".into());
    }
    if doc.get("log").and_then(|l| l.get("entries")).is_some() {
        return Some("har".into());
    }
    // Postman collection: info + item[]
    if doc.get("info").is_some() && doc.get("item").is_some() {
        return Some("postman".into());
    }
    // Insomnia export: {_type: "export", resources: [...]}
    if doc.get("_type").and_then(|v| v.as_str()) == Some("export")
        || doc.get("__export_format").is_some()
    {
        return Some("insomnia".into());
    }
    None
}

// --------------------------------------------------------------------------- shared helpers

/// Convert a JSON scalar to a display string for enum values.
fn val_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn enum_of(schema: &Value) -> Vec<String> {
    schema
        .get("enum")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().map(val_str).collect())
        .unwrap_or_default()
}

/// Join a base origin (`https://api.x.com` or with a base path) and a spec path (`/users/{id}`).
fn join_url(base: &str, path: &str) -> String {
    if path.starts_with("http://") || path.starts_with("https://") {
        return path.to_string();
    }
    let b = base.trim_end_matches('/');
    if path.is_empty() {
        return b.to_string();
    }
    if path.starts_with('/') {
        format!("{b}{path}")
    } else {
        format!("{b}/{path}")
    }
}

const METHODS: &[&str] = &[
    "get", "post", "put", "patch", "delete", "head", "options", "trace",
];

// --------------------------------------------------------------------------- OpenAPI / Swagger

fn parse_openapi(doc: &Value, base_url: Option<&str>) -> Result<ParseResult, String> {
    let base = openapi_base(doc, base_url)?;
    let paths = doc
        .get("paths")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "spec has no `paths`".to_string())?;

    let mut ops = Vec::new();
    for (path, item) in paths {
        // parameters declared at the path-item level apply to every operation.
        let shared: Vec<&Value> = item
            .get("parameters")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().collect())
            .unwrap_or_default();
        for m in METHODS {
            let Some(op) = item.get(*m) else { continue };
            if !op.is_object() {
                continue;
            }
            let url = join_url(&base, path);
            let mut fields: Vec<ImportedField> = Vec::new();
            let mut content_type: Option<String> = None;

            // path-item + operation parameters (query/path/header/cookie/body/formData)
            let mut param_list: Vec<&Value> = shared.clone();
            if let Some(arr) = op.get("parameters").and_then(|v| v.as_array()) {
                param_list.extend(arr.iter());
            }
            for p in param_list {
                let p = deref(doc, p, 0);
                let loc = p.get("in").and_then(|v| v.as_str()).unwrap_or("");
                match loc {
                    // Swagger 2.0 body parameter: a schema of properties.
                    "body" => {
                        if let Some(schema) = p.get("schema") {
                            fields.extend(body_fields(doc, schema, 0));
                            content_type.get_or_insert_with(|| "application/json".into());
                        }
                    }
                    "formData" => {
                        if let Some(f) = simple_param(doc, p, "body") {
                            fields.push(f);
                        }
                        content_type
                            .get_or_insert_with(|| "application/x-www-form-urlencoded".into());
                    }
                    "query" | "path" | "header" | "cookie" => {
                        if let Some(f) = simple_param(doc, p, loc) {
                            fields.push(f);
                        }
                    }
                    _ => {}
                }
            }

            // OpenAPI 3.x requestBody: content: { <media>: { schema } }
            if let Some(rb) = op.get("requestBody") {
                let rb = deref(doc, rb, 0);
                if let Some(content) = rb.get("content").and_then(|v| v.as_object()) {
                    // prefer JSON, else the first declared media type
                    let media = content
                        .keys()
                        .find(|k| k.contains("json"))
                        .cloned()
                        .or_else(|| content.keys().next().cloned());
                    if let Some(mt) = media {
                        content_type = Some(mt.clone());
                        if let Some(schema) = content.get(&mt).and_then(|v| v.get("schema")) {
                            fields.extend(body_fields(doc, schema, 0));
                        }
                    }
                }
            }

            let auth_required = op
                .get("security")
                .and_then(|v| v.as_array())
                .map(|a| !a.is_empty())
                .unwrap_or_else(|| {
                    doc.get("security")
                        .and_then(|v| v.as_array())
                        .map(|a| !a.is_empty())
                        .unwrap_or(false)
                });
            let summary = op
                .get("summary")
                .or_else(|| op.get("operationId"))
                .and_then(|v| v.as_str())
                .map(String::from);

            ops.push(ImportedOperation {
                method: m.to_uppercase(),
                url,
                content_type,
                auth_required,
                summary,
                fields,
            });
        }
    }
    if ops.is_empty() {
        return Err("no operations found in the spec".into());
    }
    Ok(ParseResult {
        operations: ops,
        source_label: "spec",
        confirmed: false,
        detected: "OpenAPI / Swagger".into(),
    })
}

/// Absolute base origin for a spec: explicit `base_url` wins; else OpenAPI 3.x `servers[0].url`
/// (with `{var}` defaults substituted); else Swagger 2.0 `schemes+host+basePath`.
fn openapi_base(doc: &Value, base_url: Option<&str>) -> Result<String, String> {
    if let Some(b) = base_url {
        return Ok(b.trim_end_matches('/').to_string());
    }
    if let Some(servers) = doc.get("servers").and_then(|v| v.as_array()) {
        if let Some(server) = servers.first() {
            if let Some(url) = server.get("url").and_then(|v| v.as_str()) {
                let resolved = subst_server_vars(url, server);
                if resolved.starts_with("http://") || resolved.starts_with("https://") {
                    return Ok(resolved.trim_end_matches('/').to_string());
                }
            }
        }
    }
    if let Some(host) = doc.get("host").and_then(|v| v.as_str()) {
        let scheme = doc
            .get("schemes")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|s| s.as_str())
            .unwrap_or("https");
        let base_path = doc.get("basePath").and_then(|v| v.as_str()).unwrap_or("");
        return Ok(format!(
            "{scheme}://{host}{}",
            base_path.trim_end_matches('/')
        ));
    }
    Err("the spec's server URL is relative or templated; provide a base URL (e.g. https://api.example.com)".into())
}

fn subst_server_vars(url: &str, server: &Value) -> String {
    let mut out = url.to_string();
    if let Some(vars) = server.get("variables").and_then(|v| v.as_object()) {
        for (name, def) in vars {
            if let Some(d) = def.get("default").and_then(|v| v.as_str()) {
                out = out.replace(&format!("{{{name}}}"), d);
            }
        }
    }
    out
}

/// Resolve a single `$ref` (`#/components/schemas/X`) one hop; returns the pointed value or the
/// input unchanged. `depth` guards against ref cycles.
fn deref<'a>(doc: &'a Value, v: &'a Value, depth: usize) -> &'a Value {
    if depth > 8 {
        return v;
    }
    if let Some(r) = v.get("$ref").and_then(|r| r.as_str()) {
        if let Some(p) = r.strip_prefix('#') {
            if let Some(target) = doc.pointer(p) {
                return deref(doc, target, depth + 1);
            }
        }
    }
    v
}

/// A query/path/header/cookie/formData parameter -> one field. 3.x carries type on `schema`; 2.0
/// carries it inline on the parameter.
fn simple_param(doc: &Value, p: &Value, location: &str) -> Option<ImportedField> {
    let p = deref(doc, p, 0);
    let name = p.get("name").and_then(|v| v.as_str())?.to_string();
    let schema = p.get("schema");
    let ty = schema
        .and_then(|s| s.get("type"))
        .or_else(|| p.get("type"))
        .and_then(|v| v.as_str())
        .map(String::from);
    let format = schema
        .and_then(|s| s.get("format"))
        .or_else(|| p.get("format"))
        .and_then(|v| v.as_str())
        .map(String::from);
    let enum_values = schema
        .map(enum_of)
        .filter(|e| !e.is_empty())
        .unwrap_or_else(|| enum_of(p));
    let required = p
        .get("required")
        .and_then(|v| v.as_bool())
        .unwrap_or(location == "path");
    Some(ImportedField {
        name,
        location: location.to_string(),
        ty,
        required,
        enum_values,
        format,
    })
}

/// Top-level properties of a (possibly `$ref`/`allOf`) object schema -> body fields.
fn body_fields(doc: &Value, schema: &Value, depth: usize) -> Vec<ImportedField> {
    if depth > 8 {
        return Vec::new();
    }
    let schema = deref(doc, schema, depth);
    let mut out = Vec::new();
    // allOf composes several schemas; merge their fields.
    if let Some(all) = schema.get("allOf").and_then(|v| v.as_array()) {
        for s in all {
            out.extend(body_fields(doc, s, depth + 1));
        }
    }
    // an array body: describe the element schema's fields.
    if schema.get("type").and_then(|v| v.as_str()) == Some("array") {
        if let Some(items) = schema.get("items") {
            out.extend(body_fields(doc, items, depth + 1));
        }
    }
    let required: HashSet<String> = schema
        .get("required")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    if let Some(props) = schema.get("properties").and_then(|v| v.as_object()) {
        for (name, ps) in props {
            let ps = deref(doc, ps, depth);
            let ty = ps.get("type").and_then(|v| v.as_str()).map(String::from);
            let format = ps.get("format").and_then(|v| v.as_str()).map(String::from);
            out.push(ImportedField {
                name: name.clone(),
                location: "body".into(),
                ty,
                required: required.contains(name),
                enum_values: enum_of(ps),
                format,
            });
        }
    }
    dedup_fields(out)
}

fn dedup_fields(fields: Vec<ImportedField>) -> Vec<ImportedField> {
    let mut seen = HashSet::new();
    fields
        .into_iter()
        .filter(|f| seen.insert((f.location.clone(), f.name.clone())))
        .collect()
}

// --------------------------------------------------------------------------- Postman v2.x

fn parse_postman(doc: &Value, base_url: Option<&str>) -> Result<ParseResult, String> {
    let items = doc
        .get("item")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "postman collection has no `item`".to_string())?;
    let mut ops = Vec::new();
    let mut stack: Vec<&Value> = items.iter().rev().collect();
    while let Some(it) = stack.pop() {
        // folder -> push children; request -> parse
        if let Some(children) = it.get("item").and_then(|v| v.as_array()) {
            for c in children.iter().rev() {
                stack.push(c);
            }
            continue;
        }
        if let Some(req) = it.get("request") {
            if let Some(op) = postman_request(req, base_url) {
                ops.push(op);
            }
        }
    }
    if ops.is_empty() {
        return Err("no requests found in the collection".into());
    }
    Ok(ParseResult {
        operations: ops,
        source_label: "spec",
        confirmed: false,
        detected: "Postman collection".into(),
    })
}

fn postman_request(req: &Value, base_url: Option<&str>) -> Option<ImportedOperation> {
    let method = req
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("GET")
        .to_uppercase();
    let (raw_url, query_keys) = postman_url(req.get("url"));
    let url = rebase(&raw_url, base_url)?;
    let mut fields: Vec<ImportedField> = query_keys
        .into_iter()
        .map(|k| ImportedField {
            name: k,
            location: "query".into(),
            ty: None,
            required: false,
            enum_values: vec![],
            format: None,
        })
        .collect();

    let mut content_type = header_value(req.get("header"), "content-type");
    if let Some(body) = req.get("body") {
        let (bf, ct) = postman_body(body);
        fields.extend(bf);
        if content_type.is_none() {
            content_type = ct;
        }
    }
    let auth_required =
        req.get("auth").is_some() || header_value(req.get("header"), "authorization").is_some();
    Some(ImportedOperation {
        method,
        url,
        content_type,
        auth_required,
        summary: None,
        fields: dedup_fields(fields),
    })
}

/// Postman url is a string or `{raw, host[], path[], query:[{key}]}`. Returns (raw_url, query_keys).
fn postman_url(u: Option<&Value>) -> (String, Vec<String>) {
    match u {
        Some(Value::String(s)) => (s.clone(), Vec::new()),
        Some(Value::Object(o)) => {
            let raw = o
                .get("raw")
                .and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_else(|| {
                    let host = o
                        .get("host")
                        .and_then(|v| v.as_array())
                        .map(|a| join_parts(a, "."))
                        .unwrap_or_default();
                    let path = o
                        .get("path")
                        .and_then(|v| v.as_array())
                        .map(|a| join_parts(a, "/"))
                        .unwrap_or_default();
                    format!("{host}/{path}")
                });
            let query = o
                .get("query")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|q| q.get("key").and_then(|k| k.as_str()).map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            (raw, query)
        }
        _ => (String::new(), Vec::new()),
    }
}

fn join_parts(a: &[Value], sep: &str) -> String {
    a.iter()
        .filter_map(|x| x.as_str())
        .collect::<Vec<_>>()
        .join(sep)
}

fn postman_body(body: &Value) -> (Vec<ImportedField>, Option<String>) {
    let mode = body.get("mode").and_then(|v| v.as_str()).unwrap_or("");
    match mode {
        "urlencoded" | "formdata" => {
            let key = mode;
            let fields = body
                .get(key)
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|kv| kv.get("key").and_then(|k| k.as_str()).map(String::from))
                        .map(|k| ImportedField {
                            name: k,
                            location: "body".into(),
                            ty: None,
                            required: false,
                            enum_values: vec![],
                            format: None,
                        })
                        .collect()
                })
                .unwrap_or_default();
            let ct = if mode == "urlencoded" {
                "application/x-www-form-urlencoded"
            } else {
                "multipart/form-data"
            };
            (fields, Some(ct.to_string()))
        }
        "raw" => {
            let text = body.get("raw").and_then(|v| v.as_str()).unwrap_or("");
            let fields = json_body_fields(text);
            let ct = if fields.is_empty() {
                None
            } else {
                Some("application/json".to_string())
            };
            (fields, ct)
        }
        _ => (Vec::new(), None),
    }
}

/// Best-effort: parse a raw request body as JSON and take its top-level keys as body fields.
fn json_body_fields(text: &str) -> Vec<ImportedField> {
    let v: Value = match serde_json::from_str(text.trim()) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let obj = match &v {
        Value::Object(_) => Some(&v),
        Value::Array(a) => a.iter().find(|x| x.is_object()),
        _ => None,
    };
    let Some(Value::Object(map)) = obj else {
        return Vec::new();
    };
    map.iter()
        .map(|(k, val)| ImportedField {
            name: k.clone(),
            location: "body".into(),
            ty: json_type(val),
            required: false,
            enum_values: vec![],
            format: None,
        })
        .collect()
}

fn json_type(v: &Value) -> Option<String> {
    Some(
        match v {
            Value::String(_) => "string",
            Value::Bool(_) => "boolean",
            Value::Number(n) if n.is_f64() => "number",
            Value::Number(_) => "integer",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
            Value::Null => return None,
        }
        .to_string(),
    )
}

fn header_value(headers: Option<&Value>, name: &str) -> Option<String> {
    let arr = headers?.as_array()?;
    for h in arr {
        if h.get("key")
            .and_then(|k| k.as_str())
            .map(|k| k.eq_ignore_ascii_case(name))
            .unwrap_or(false)
        {
            return h
                .get("value")
                .and_then(|v| v.as_str())
                .map(String::from)
                .or(Some(String::new()));
        }
    }
    None
}

/// Replace the origin of a captured/declared URL with the user-supplied base, when given. Also
/// resolves `{{var}}`-style hosts to the base. Returns None for an unusable URL.
/// Extract query-parameter names from the `?a=1&b=2` portion of a plain URL string. Used for
/// sources (Insomnia) that carry the query only inline in the URL, not as a structured field list.
fn query_keys_from_url(url: &str) -> Vec<String> {
    let Some((_, q)) = url.split_once('?') else {
        return Vec::new();
    };
    q.split('&')
        .filter_map(|pair| {
            let key = pair.split(['=', '#']).next().unwrap_or("").trim();
            (!key.is_empty()).then(|| key.to_string())
        })
        .collect()
}

fn rebase(raw: &str, base_url: Option<&str>) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let Some(base) = base_url else {
        // no override: keep only if it has a real host
        return if raw.starts_with("http") {
            Some(raw.to_string())
        } else {
            None
        };
    };
    // strip scheme+authority from raw, keep the path+query
    let path = if let Some(rest) = raw
        .strip_prefix("http://")
        .or_else(|| raw.strip_prefix("https://"))
    {
        rest.find('/').map(|i| &rest[i..]).unwrap_or("/")
    } else if let Some(i) = raw.find("/") {
        // "{{base}}/api/x" or "host/api/x" -> take from first '/'
        &raw[i..]
    } else {
        "/"
    };
    Some(join_url(base, path))
}

// --------------------------------------------------------------------------- HAR

fn parse_har(doc: &Value) -> Result<ParseResult, String> {
    let entries = doc
        .get("log")
        .and_then(|l| l.get("entries"))
        .and_then(|v| v.as_array())
        .ok_or_else(|| "HAR has no log.entries".to_string())?;
    let mut ops = Vec::new();
    for e in entries {
        let Some(req) = e.get("request") else {
            continue;
        };
        let method = req
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("GET")
            .to_uppercase();
        let Some(url) = req.get("url").and_then(|v| v.as_str()) else {
            continue;
        };
        if !url.starts_with("http") {
            continue;
        }
        let mut fields: Vec<ImportedField> = req
            .get("queryString")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|q| q.get("name").and_then(|n| n.as_str()).map(String::from))
                    .map(|k| ImportedField {
                        name: k,
                        location: "query".into(),
                        ty: None,
                        required: false,
                        enum_values: vec![],
                        format: None,
                    })
                    .collect()
            })
            .unwrap_or_default();

        let mut content_type = None;
        if let Some(pd) = req.get("postData") {
            content_type = pd
                .get("mimeType")
                .and_then(|v| v.as_str())
                .map(|s| s.split(';').next().unwrap_or(s).trim().to_string());
            if let Some(params) = pd.get("params").and_then(|v| v.as_array()) {
                for p in params {
                    if let Some(n) = p.get("name").and_then(|v| v.as_str()) {
                        fields.push(ImportedField {
                            name: n.to_string(),
                            location: "body".into(),
                            ty: None,
                            required: false,
                            enum_values: vec![],
                            format: None,
                        });
                    }
                }
            } else if let Some(text) = pd.get("text").and_then(|v| v.as_str()) {
                fields.extend(json_body_fields(text));
            }
        }
        let auth_required = req
            .get("headers")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter().any(|h| {
                    h.get("name")
                        .and_then(|n| n.as_str())
                        .map(|n| {
                            n.eq_ignore_ascii_case("authorization")
                                || n.eq_ignore_ascii_case("cookie")
                        })
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false);

        ops.push(ImportedOperation {
            method,
            url: url.to_string(),
            content_type,
            auth_required,
            summary: None,
            fields: dedup_fields(fields),
        });
    }
    if ops.is_empty() {
        return Err("no requests found in the HAR".into());
    }
    Ok(ParseResult {
        operations: ops,
        source_label: "observed",
        confirmed: true,
        detected: "HAR capture".into(),
    })
}

// --------------------------------------------------------------------------- Insomnia v4

fn parse_insomnia(doc: &Value, base_url: Option<&str>) -> Result<ParseResult, String> {
    let resources = doc
        .get("resources")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "insomnia export has no `resources`".to_string())?;
    let mut ops = Vec::new();
    for r in resources {
        if r.get("_type").and_then(|v| v.as_str()) != Some("request") {
            continue;
        }
        let method = r
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("GET")
            .to_uppercase();
        let Some(raw_url) = r.get("url").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(url) = rebase(raw_url, base_url) else {
            continue;
        };
        let mut fields: Vec<ImportedField> = r
            .get("parameters")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|p| p.get("name").and_then(|n| n.as_str()).map(String::from))
                    .map(|k| ImportedField {
                        name: k,
                        location: "query".into(),
                        ty: None,
                        required: false,
                        enum_values: vec![],
                        format: None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        // Insomnia may carry query params inline in the URL rather than in `parameters`; capture
        // those too (dedup below drops any that appear in both).
        for k in query_keys_from_url(raw_url) {
            fields.push(ImportedField {
                name: k,
                location: "query".into(),
                ty: None,
                required: false,
                enum_values: vec![],
                format: None,
            });
        }
        let mut content_type = None;
        if let Some(body) = r.get("body") {
            content_type = body
                .get("mimeType")
                .and_then(|v| v.as_str())
                .map(String::from);
            if let Some(params) = body.get("params").and_then(|v| v.as_array()) {
                for p in params {
                    if let Some(n) = p.get("name").and_then(|v| v.as_str()) {
                        fields.push(ImportedField {
                            name: n.to_string(),
                            location: "body".into(),
                            ty: None,
                            required: false,
                            enum_values: vec![],
                            format: None,
                        });
                    }
                }
            } else if let Some(text) = body.get("text").and_then(|v| v.as_str()) {
                fields.extend(json_body_fields(text));
            }
        }
        let auth_required = r
            .get("authentication")
            .map(|a| a.is_object() && !a.as_object().map(|o| o.is_empty()).unwrap_or(true))
            .unwrap_or(false);
        ops.push(ImportedOperation {
            method,
            url,
            content_type,
            auth_required,
            summary: None,
            fields: dedup_fields(fields),
        });
    }
    if ops.is_empty() {
        return Err("no requests found in the insomnia export".into());
    }
    Ok(ParseResult {
        operations: ops,
        source_label: "spec",
        confirmed: false,
        detected: "Insomnia export".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insomnia_query_from_url() {
        assert_eq!(
            query_keys_from_url("http://x.test/a?q=1&page=2"),
            vec!["q", "page"]
        );
        assert!(query_keys_from_url("http://x.test/a").is_empty());
        let spec = r#"{"_type":"export","__export_format":4,"resources":[
            {"_type":"request","_id":"r1","method":"GET","url":"http://ins.test/things?q=x&limit=5"}]}"#;
        let r = parse(spec, "auto", None).expect("parse");
        let names: Vec<&str> = r.operations[0]
            .fields
            .iter()
            .map(|f| f.name.as_str())
            .collect();
        assert!(names.contains(&"q") && names.contains(&"limit"));
    }

    #[test]
    fn openapi3_json_extracts_operations_and_body_fields() {
        let spec = r#"{
          "openapi":"3.0.0",
          "servers":[{"url":"https://api.example.com/v1"}],
          "paths":{
            "/users/{id}":{
              "get":{"summary":"get user","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"integer"}},{"name":"verbose","in":"query","schema":{"type":"boolean"}}],"security":[{"bearer":[]}]},
              "post":{"requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["name"],"properties":{"name":{"type":"string"},"role":{"type":"string","enum":["admin","user"]}}}}}}}
            }
          }
        }"#;
        let r = parse(spec, "auto", None).expect("parse");
        assert_eq!(r.source_label, "spec");
        assert!(!r.confirmed);
        // GET + POST
        let get = r.operations.iter().find(|o| o.method == "GET").unwrap();
        assert_eq!(get.url, "https://api.example.com/v1/users/{id}");
        assert!(get.auth_required);
        assert!(
            get.fields
                .iter()
                .any(|f| f.name == "id" && f.location == "path" && f.required)
        );
        assert!(
            get.fields
                .iter()
                .any(|f| f.name == "verbose" && f.location == "query")
        );
        let post = r.operations.iter().find(|o| o.method == "POST").unwrap();
        assert_eq!(post.content_type.as_deref(), Some("application/json"));
        let role = post.fields.iter().find(|f| f.name == "role").unwrap();
        assert_eq!(role.location, "body");
        assert_eq!(role.enum_values, vec!["admin", "user"]);
        assert!(post.fields.iter().any(|f| f.name == "name" && f.required));
    }

    #[test]
    fn swagger2_uses_host_basepath_and_body_param() {
        let spec = r#"{
          "swagger":"2.0","host":"api.example.com","basePath":"/v2","schemes":["https"],
          "paths":{"/login":{"post":{"parameters":[{"in":"body","name":"creds","schema":{"type":"object","properties":{"user":{"type":"string"},"pass":{"type":"string"}}}}]}}}
        }"#;
        let r = parse(spec, "openapi", None).expect("parse");
        let op = &r.operations[0];
        assert_eq!(op.url, "https://api.example.com/v2/login");
        assert!(
            op.fields
                .iter()
                .any(|f| f.name == "user" && f.location == "body")
        );
        assert!(
            op.fields
                .iter()
                .any(|f| f.name == "pass" && f.location == "body")
        );
    }

    #[test]
    fn har_is_observed_and_confirmed() {
        let har = r#"{"log":{"entries":[
          {"request":{"method":"POST","url":"https://api.example.com/orders?ref=abc","headers":[{"name":"Authorization","value":"x"}],"queryString":[{"name":"ref","value":"abc"}],"postData":{"mimeType":"application/json","text":"{\"item\":1,\"qty\":2}"}},"response":{"status":201}}
        ]}}"#;
        let r = parse(har, "auto", None).expect("parse");
        assert_eq!(r.source_label, "observed");
        assert!(r.confirmed);
        let op = &r.operations[0];
        assert!(op.auth_required);
        assert!(
            op.fields
                .iter()
                .any(|f| f.name == "ref" && f.location == "query")
        );
        assert!(
            op.fields
                .iter()
                .any(|f| f.name == "item" && f.location == "body")
        );
        assert!(
            op.fields
                .iter()
                .any(|f| f.name == "qty" && f.location == "body")
        );
    }

    #[test]
    fn postman_rebases_and_reads_body() {
        let coll = r#"{"info":{"name":"c"},"item":[
          {"name":"folder","item":[
            {"name":"create","request":{"method":"POST","url":{"raw":"{{base}}/api/widgets","host":["{{base}}"],"path":["api","widgets"]},"header":[{"key":"Content-Type","value":"application/json"}],"body":{"mode":"raw","raw":"{\"name\":\"x\",\"price\":5}"}}}
          ]}
        ]}"#;
        let r = parse(coll, "auto", Some("https://shop.example.com")).expect("parse");
        let op = &r.operations[0];
        assert_eq!(op.url, "https://shop.example.com/api/widgets");
        assert!(
            op.fields
                .iter()
                .any(|f| f.name == "name" && f.location == "body")
        );
        assert!(
            op.fields
                .iter()
                .any(|f| f.name == "price" && f.location == "body")
        );
    }

    #[test]
    fn detects_yaml_openapi() {
        let spec = "openapi: 3.0.0\nservers:\n  - url: https://api.example.com\npaths:\n  /ping:\n    get:\n      summary: ping\n";
        let r = parse(spec, "auto", None).expect("parse");
        assert_eq!(r.operations.len(), 1);
        assert_eq!(r.operations[0].url, "https://api.example.com/ping");
    }
}

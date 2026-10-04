//! Turning what a scan saw into a stable description of a surface.
//!
//! The unit here is an operation rather than a request: a method and an endpoint whose
//! identifier-shaped path segments have been replaced by placeholders, so that four
//! thousand captured requests collapse into the couple of hundred things the application
//! actually exposes. That collapse is what makes two other questions answerable, and
//! neither of them can be asked of a flat list of requests:
//!
//! - **Coverage.** Which of these endpoints have been tested for what. Every tester
//!   tracks this by hand in a spreadsheet, because no tool holds the model it needs.
//! - **Change.** What is different since last time: a new endpoint, a parameter that
//!   gained values, a response that stopped being what it was. That is the retest, and
//!   consultancies bill for it and do it by rereading the old report.
//!
//! This crate is pure. No database, no network, no opinion about where the surface came
//! from or what stores it, which is what lets a desktop window and a hosted platform
//! share one description instead of two that drift.
//!
//! ## The heuristics are the interesting part
//!
//! [`normalize_endpoint`] has to decide whether a path segment is a name or an
//! identifier, and it is wrong in both directions at the edges. Collapsing too eagerly
//! merges two real endpoints into one and hides a bug in whichever got merged away.
//! Collapsing too shyly leaves ten thousand rows that are all the same endpoint with a
//! different number in it, which is the state this was written to escape.
//!
//! [`is_junk_endpoint`] exists for the same reason from the other side: a crawler finds
//! things that are not endpoints, and a surface full of them is one nobody reads.
//!
//! ## A third copy exists and this is not it
//!
//! The same taxonomy is implemented in JavaScript, in the dashboard's surface model, so
//! the rendered view and the stored graph agree. Extracting this crate does not fix that:
//! a browser cannot call a Rust crate without a compile step that does not exist here
//! yet. It is written down so the next person knows there are two and not one.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// An `operation` asset's value is "<METHOD> <url>", not a bare URL. Without
/// stripping the verb, strip_scheme sees a scheme of "GET https" (a space is not
/// a legal scheme character), gives up, and host_of returns "GET https:" -- so
/// every operation asset was invisible to the capture blacklist, both at ingest
/// and in the retroactive purge.
pub const HTTP_METHODS: [&str; 9] = [
    "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT",
];

/// Registrable domain, approximated as the last two dot-labels (IPv4 is its own root).
/// Two-label public suffixes people register directly under (a partial PSL covering the common ones).
/// Without these, `root_of("vmc.gov.in")` naively returns `gov.in` and treats the target as a
/// subdomain of the whole `.gov.in` space - which then shows up as a bogus scannable `gov.in` asset.
pub static MULTI_SUFFIXES: &[&str] = &[
    // India
    "gov.in", "nic.in", "ac.in", "co.in", "net.in", "org.in", "edu.in", "res.in", "gen.in",
    "firm.in", "ind.in", "mil.in", // UK
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk", "sch.uk",
    "nhs.uk", // Australia / NZ
    "com.au", "net.au", "org.au", "gov.au", "edu.au", "id.au", "co.nz", "govt.nz", "org.nz",
    "ac.nz", // Others (common)
    "co.jp", "or.jp", "ne.jp", "go.jp", "ac.jp", "com.br", "gov.br", "org.br", "com.cn", "gov.cn",
    "edu.cn", "org.cn", "net.cn", "com.sg", "gov.sg", "edu.sg", "com.my", "gov.my", "org.my",
    "co.za", "gov.za", "org.za", "com.mx", "gob.mx", "com.tr", "gov.tr", "edu.tr", "co.id",
    "go.id", "ac.id", "com.pk", "gov.pk", "edu.pk", "com.bd", "gov.bd", "com.sa", "gov.sa",
    "com.ng", "gov.ng",
];

/// Static-resource extensions worth tracking as `static` assets (code/config/media). JS/CSS/JSON are
/// the change-monitoring targets; media is inventoried too so appeared/disappeared is complete.
pub const STATIC_EXTS: &[&str] = &[
    "js", "mjs", "cjs", "css", "map", "json", "wasm", "xml", "png", "jpg", "jpeg", "gif", "svg",
    "ico", "webp", "bmp", "woff", "woff2", "ttf", "eot", "otf", "mp4", "webm", "mp3", "wav", "pdf",
];

pub fn strip_scheme(s: &str) -> &str {
    if let Some(idx) = s.find("://") {
        let scheme = &s[..idx];
        if !scheme.is_empty()
            && scheme
                .chars()
                .next()
                .map(|c| c.is_ascii_alphabetic())
                .unwrap_or(false)
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
        {
            return &s[idx + 3..];
        }
    }
    s
}

pub fn is_ipv4(host: &str) -> bool {
    let parts: Vec<&str> = host.split('.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 3 && p.chars().all(|c| c.is_ascii_digit()))
}

pub fn strip_method(s: &str) -> &str {
    if let Some((head, rest)) = s.split_once(' ') {
        if HTTP_METHODS.contains(&head.to_ascii_uppercase().as_str()) {
            return rest.trim_start();
        }
    }
    s
}

/// Bare host: strip method / scheme / path / query / userinfo / port. Lowercased.
pub fn host_of(target: &str) -> String {
    let s = target.trim();
    if s.is_empty() {
        return String::new();
    }
    let s = strip_method(s);
    let mut s = strip_scheme(s).to_string();
    // path / query / fragment
    s = s
        .split('/')
        .next()
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("")
        .split('#')
        .next()
        .unwrap_or("")
        .to_string();
    // userinfo
    if let Some(pos) = s.rfind('@') {
        s = s[pos + 1..].to_string();
    }
    // brackets / port
    if s.starts_with('[') {
        if let Some(end) = s.find(']') {
            s = s[1..end].to_string();
        }
    } else if let Some(pos) = s.find(':') {
        s = s[..pos].to_string();
    }
    s.to_lowercase()
}

/// True if `host` is (exactly) a public suffix under which people register - a bare TLD label like
/// `com`/`in`, or a two-label suffix like `gov.in`/`co.uk`. Such a host is never a real target: you
/// cannot meaningfully scan "gov.in", and the planner must not suggest it.
pub fn is_public_suffix(host: &str) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() {
        return false;
    }
    if !h.contains('.') {
        return true; // bare TLD: com, net, in, ...
    }
    MULTI_SUFFIXES.contains(&h.as_str())
}

pub fn root_of(host: &str) -> String {
    if host.is_empty() {
        return String::new();
    }
    if is_ipv4(host) {
        return host.to_string();
    }
    let parts: Vec<&str> = host.split('.').filter(|p| !p.is_empty()).collect();
    if parts.len() <= 2 {
        return host.to_string();
    }
    // If the last two labels form a known two-label public suffix (gov.in, co.uk), the registrable
    // domain is the last THREE labels (vmc.gov.in), not two (gov.in).
    let last2 = parts[parts.len() - 2..].join(".");
    if MULTI_SUFFIXES.contains(&last2.as_str()) && parts.len() >= 3 {
        return parts[parts.len() - 3..].join(".");
    }
    last2
}

pub fn is_subdomain(host: &str, root: &str) -> bool {
    // `root` is `root_of(host)`, so a host is a subdomain exactly when it differs from its own
    // registrable root (e.g. vmc.gov.in == root -> not a subdomain; www.vmc.gov.in != root -> is).
    !host.is_empty() && host != root
}

pub fn port_of(target: &str) -> String {
    let s = strip_scheme(target.trim());
    // host[:port][/...]; take digits after the first ':' before a path/query
    if let Some(colon) = s.find(':') {
        let after = &s[colon + 1..];
        let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
        if !digits.is_empty() {
            return digits;
        }
    }
    String::new()
}

/// Path (with query stripped) for endpoint normalization.
pub fn path_no_query(target: &str) -> String {
    let s = strip_scheme(target.trim());
    match s.find('/') {
        Some(i) => s[i..]
            .split('?')
            .next()
            .unwrap_or("")
            .split('#')
            .next()
            .unwrap_or("")
            .to_string(),
        None => String::new(),
    }
}

pub fn is_id_like(seg: &str) -> bool {
    if seg.is_empty() {
        return false;
    }
    // pure numeric (ids, pagination)
    if seg.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }
    // uuid
    let hyphens = seg.matches('-').count();
    if seg.len() == 36 && hyphens == 4 && seg.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
        return true;
    }
    // long hex (hashes, tokens)
    if seg.len() >= 16 && seg.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    false
}

/// Canonical endpoint value = authority + normalized path (id-like segments ->
/// `{id}`), query dropped. The authority keeps a NON-DEFAULT port (`host:8088`)
/// so a scan launched from this endpoint reaches the right service instead of
/// falling back to :80; standard ports (80/443) are implied and omitted.
pub fn normalize_endpoint(target: &str) -> String {
    let host = host_of(target);
    let authority = match port_of(target).as_str() {
        "" | "80" | "443" => host,
        p => format!("{host}:{p}"),
    };
    // Decode `{`/`}` (a URL type percent-encodes them) so a route template like
    // `/rest/basket/{id}` reads cleanly instead of `/rest/basket/%7bid%7d`.
    let path = path_no_query(target)
        .replace("%7B", "{")
        .replace("%7b", "{")
        .replace("%7D", "}")
        .replace("%7d", "}");
    if path.is_empty() {
        return format!("{authority}/");
    }
    let norm: Vec<String> = path
        .split('/')
        .map(|seg| {
            if is_id_like(seg) {
                "{id}".to_string()
            } else {
                seg.to_string()
            }
        })
        .collect();
    format!("{authority}{}", norm.join("/"))
}

/// True if a discovered endpoint value is crawler noise rather than a real route.
/// Parsing minified JS bundles (and browser captures of SPAs) leaks unresolved
/// template literals - `${this.hostServer}/rest/...`, which URL-encode to
/// `%7b..%7d` - plus backticks and stray angle brackets. These are not endpoints;
/// they pollute the asset graph and the planner's targets, so we drop them at
/// ingest instead of scanning `${e}` as if it were a path.
pub fn is_junk_endpoint(value: &str) -> bool {
    let v = value.to_ascii_lowercase();
    // Unresolved JS template *variables* - `${...}`, raw or URL-encoded as
    // `$%7b..%7d` / `%24%7b..`. NB: a bare `{id}` (encoded `%7bid%7d`) is the
    // graph's own id-normalization placeholder and is legitimate, so we key on
    // the leading `$`/`%24` that marks a template expression, not bare braces.
    v.contains("${")
        || v.contains("$%7b")
        || v.contains("%24%7b")
        || value.contains('`')
        || value.contains('<')
        || value.contains('>')
        || value.contains(' ')
}

/// Does a query part that carried no `=` look like a param NAME rather than a value
/// somebody passed bare?
///
/// The tracer redacts before it sends, and `cfx_capture::reduce` drops these at the
/// source. This is here because the source is not the only thing that reaches this
/// endpoint: an older installed tracer sends what its build does, and a trace can be
/// posted by anything holding a workspace token. Every query name becomes a `param` asset,
/// so trusting the client's redaction means a credential gets persisted and shown in the
/// UI. The rule is deliberately the same as the tracer's so the two cannot disagree about
/// what a name is.
pub fn looks_like_a_param_name(p: &str) -> bool {
    if p.is_empty() || p.len() > 20 {
        return false;
    }
    if p.bytes()
        .any(|b| matches!(b, b'%' | b'+' | b'/' | b'=' | b':' | b'@'))
    {
        return false;
    }
    if !p
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'[' | b']' | b'~'))
    {
        return false;
    }
    // Sixteen or more hex characters is an id or a digest, not something anybody named.
    !(p.len() >= 16 && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Query param names + their location, for `param` child assets.
pub fn query_params(target: &str) -> Vec<String> {
    let s = strip_scheme(target.trim());
    let q = match s.find('?') {
        Some(i) => &s[i + 1..],
        None => return Vec::new(),
    };
    let q = q.split('#').next().unwrap_or("");
    q.split('&')
        .filter_map(|kv| {
            match kv.split_once('=') {
                // A "value" of nothing but `=` is base64 padding, so the split landed
                // inside a bare token and the "name" is the token's own prefix.
                Some((_, v)) if !v.is_empty() && v.bytes().all(|b| b == b'=') => None,
                Some((k, _)) => {
                    let name = k.trim();
                    if name.is_empty() {
                        None
                    } else {
                        Some(name.to_string())
                    }
                }
                // No `=` at all: not demonstrably a name, so it is kept only if it reads
                // like one.
                None => {
                    let name = kv.trim();
                    looks_like_a_param_name(name).then(|| name.to_string())
                }
            }
        })
        .collect()
}

/// Resolve the most specific EXISTING asset a vuln finding should hang off: the operation
/// (method × endpoint) when the method is known and the recon pass already mapped it, else the
/// endpoint, else the host we already have. Findings attach to surface that recon discovered -
/// they never mint new surface here - so this only looks up + falls back, never upserts.
/// Does a concrete request path match a (possibly templated) stored path? Same segment count, and
/// each stored segment either equals the concrete one literally or is a `{placeholder}`. This lets a
/// finding proven against `.../users/v1/1` link to the templated operation `.../users/v1/{username}`
/// (the inject/fuzz engines fill templates with a sample before probing, and template scans hit
/// concrete object ids), without teaching the open-core engine anything about asset UUIDs.
pub fn path_matches_template(concrete: &str, template: &str) -> bool {
    let c: Vec<&str> = concrete.split('/').collect();
    let t: Vec<&str> = template.split('/').collect();
    if c.len() != t.len() {
        return false;
    }
    c.iter()
        .zip(&t)
        .all(|(cs, ts)| (ts.starts_with('{') && ts.ends_with('}')) || cs == ts)
}

/// Provenance / volatile keys that don't define an asset's *state* and must not affect the hash/diff.
pub fn is_volatile(key: &str) -> bool {
    matches!(
        key,
        "target" | "source" | "raw" | "seen_at" | "timestamp" | "url"
    )
}

/// SHA-256 over the canonicalized snapshot (stable regardless of JSON key order): the cheap gate for
/// "did this asset change". Type-prefixed so different asset types never collide.
pub fn content_hash(atype: &str, snapshot: &Value) -> String {
    let mut pairs: Vec<(String, String)> = Vec::new();
    if let Some(obj) = snapshot.as_object() {
        for (k, v) in obj {
            if is_volatile(k) || v.is_null() {
                continue;
            }
            pairs.push((k.clone(), v.to_string()));
        }
    }
    pairs.sort();
    let canon = pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("\n");
    let mut h = Sha256::new();
    h.update(atype.as_bytes());
    h.update(b"\n");
    h.update(canon.as_bytes());
    hex::encode(h.finalize())
}

/// Field-level diff between two snapshots → rich entries `{field, op, old, new, category, label,
/// significance}`. Volatile keys and no-op changes are skipped.
pub fn diff_snapshots(atype: &str, old: &Value, new: &Value) -> Vec<Value> {
    use std::collections::BTreeSet;
    let oe = old.as_object();
    let ne = new.as_object();
    let mut keys: BTreeSet<String> = BTreeSet::new();
    if let Some(o) = oe {
        keys.extend(o.keys().filter(|k| !is_volatile(k)).cloned());
    }
    if let Some(n) = ne {
        keys.extend(n.keys().filter(|k| !is_volatile(k)).cloned());
    }
    let mut out = Vec::new();
    for k in keys {
        let ov = oe.and_then(|o| o.get(&k)).filter(|v| !v.is_null());
        let nv = ne.and_then(|n| n.get(&k)).filter(|v| !v.is_null());
        let (op, old_v, new_v) = match (ov, nv) {
            (None, Some(n)) => ("added", Value::Null, n.clone()),
            (Some(o), None) => ("removed", o.clone(), Value::Null),
            (Some(o), Some(n)) if o != n => ("modified", o.clone(), n.clone()),
            _ => continue,
        };
        let (category, significance) = classify(atype, &k, op);
        out.push(json!({
            "field": k,
            "op": op,
            "old": old_v,
            "new": new_v,
            "category": category,
            "label": change_label(&k, op, &old_v, &new_v),
            "significance": significance,
        }));
    }
    out
}

/// Map a (type, field, op) delta to a semantic category + significance. Conservative defaults; widen
/// as the snapshot fields grow.
pub fn classify(atype: &str, field: &str, op: &str) -> (&'static str, &'static str) {
    match (atype, field) {
        ("endpoint", "status_code") => ("status_changed", "notable"),
        ("endpoint", "auth") => ("auth_changed", "security"),
        ("endpoint", "tech") => ("tech_changed", "notable"),
        ("endpoint", "service") => ("service_changed", "notable"),
        ("endpoint", "title") => ("title_changed", "cosmetic"),
        ("endpoint", "methods") => ("method_changed", "notable"),
        ("endpoint", "content_hash") => ("content_changed", "notable"),
        // Operations (method × endpoint) carry the per-probe/response state, so change
        // tracking is meaningful here (per-operation), not on the method-agnostic endpoint.
        ("operation", "status_code") => ("status_changed", "notable"),
        ("operation", "auth") => ("auth_changed", "security"),
        ("operation", "tech") => ("tech_changed", "notable"),
        ("operation", "service") => ("service_changed", "notable"),
        ("operation", "title") => ("title_changed", "cosmetic"),
        ("operation", "content_hash") => ("content_changed", "notable"),
        ("port", "service") => ("service_changed", "notable"),
        ("port", "banner") => ("banner_changed", "notable"),
        ("port", "status") => ("port_status_changed", "notable"),
        ("static", "content_hash") => ("content_changed", "security"),
        ("static", "etag") | ("static", "last_modified") => ("content_changed", "notable"),
        _ if op == "added" => ("attr_added", "notable"),
        _ if op == "removed" => ("attr_removed", "notable"),
        _ => ("modified", "notable"),
    }
}

/// Human one-liner for a single field delta, e.g. "Status 200 → 403".
pub fn change_label(field: &str, op: &str, old: &Value, new: &Value) -> String {
    let pretty = |v: &Value| -> String {
        match v {
            Value::Null => "∅".into(),
            Value::String(s) => s.clone(),
            other => other.to_string(),
        }
    };
    let name = field.replace('_', " ");
    match op {
        "added" => format!("{name} {}", pretty(new)),
        "removed" => format!("{name} removed ({})", pretty(old)),
        _ => format!("{name} {} → {}", pretty(old), pretty(new)),
    }
}

/// Roll diff entries up into a one-line summary + the max significance (security > notable > cosmetic).
pub fn summarize(entries: &[Value]) -> (String, String) {
    let rank = |s: &str| match s {
        "security" => 3,
        "notable" => 2,
        _ => 1,
    };
    let mut best = "cosmetic";
    let mut labels: Vec<String> = Vec::new();
    for e in entries {
        if let Some(sig) = e.get("significance").and_then(|v| v.as_str()) {
            if rank(sig) > rank(best) {
                best = match sig {
                    "security" => "security",
                    "notable" => "notable",
                    _ => "cosmetic",
                };
            }
        }
        if let Some(l) = e.get("label").and_then(|v| v.as_str()) {
            labels.push(l.to_string());
        }
    }
    let summary = if labels.len() > 3 {
        format!("{}; +{} more", labels[..3].join("; "), labels.len() - 3)
    } else {
        labels.join("; ")
    };
    (summary, best.to_string())
}

/// If a discovered URL points at a static file, return its (lowercased) extension. Strips the query
/// and fragment first so `/app.js?v=3` still classifies as `js`.
pub fn static_ext(value: &str) -> Option<String> {
    let path = value.split(['?', '#']).next().unwrap_or(value);
    let last = path.rsplit('/').next().unwrap_or(path);
    last.rsplit_once('.')
        .map(|(_, e)| e.to_lowercase())
        .filter(|e| STATIC_EXTS.contains(&e.as_str()))
}

/// Merge an asset's per-type `attrs` onto its base observation snapshot, so the stored snapshot
/// carries the state fields the diff engine compares (status, service, banner, tech, …).
pub fn snap_with_attrs(base: &Value, attrs: &Value) -> Value {
    let mut m = base.as_object().cloned().unwrap_or_default();
    if let Some(a) = attrs.as_object() {
        for (k, v) in a {
            m.insert(k.clone(), v.clone());
        }
    }
    Value::Object(m)
}

/// A blacklist rule with its regex pre-compiled (for kind "regex"), so the ingest
/// loop matches without recompiling per event. Matching a captured request uses its
/// bare `host` and canonical `value` (the normalized endpoint value at ingest, or the
/// asset value when purging).
pub struct CompiledRule {
    kind: String,
    pattern: String, // trimmed + lowercased for the non-regex kinds
    regex: Option<regex::Regex>,
}

impl CompiledRule {
    fn hit(&self, host: &str, value: &str) -> bool {
        // A regex rule matches against the value or the host (case-insensitive, compiled).
        if let Some(re) = &self.regex {
            return re.is_match(value) || re.is_match(host);
        }
        if self.pattern.is_empty() {
            return false;
        }
        let host = host.to_lowercase();
        let value = value.to_lowercase();
        match self.kind.as_str() {
            // A registrable domain and everything under it.
            "domain" => host == self.pattern || host.ends_with(&format!(".{}", self.pattern)),
            // One exact host (a subdomain), and its endpoints (same host).
            "host" | "subdomain" => host == self.pattern,
            // One exact normalized endpoint value (tolerant of a trailing slash).
            "endpoint" => value.trim_end_matches('/') == self.pattern.trim_end_matches('/'),
            // Substring of the value or host - the flexible catch-all.
            "pattern" => value.contains(&self.pattern) || host.contains(&self.pattern),
            _ => false,
        }
    }
}

/// Compile (kind, pattern) rules once. A "regex" rule whose pattern does not compile is
/// dropped (add-time validates, so this is just a safety net).
pub fn compile_blacklist(rules: &[(String, String)]) -> Vec<CompiledRule> {
    rules
        .iter()
        .filter_map(|(k, p)| {
            if k == "regex" {
                let re = regex::RegexBuilder::new(p)
                    .case_insensitive(true)
                    .build()
                    .ok()?;
                Some(CompiledRule {
                    kind: k.clone(),
                    pattern: p.clone(),
                    regex: Some(re),
                })
            } else {
                Some(CompiledRule {
                    kind: k.clone(),
                    pattern: p.trim().to_lowercase(),
                    regex: None,
                })
            }
        })
        .collect()
}

/// True if any compiled rule matches.
pub fn blacklisted(rules: &[CompiledRule], host: &str, value: &str) -> bool {
    rules.iter().any(|r| r.hit(host, value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_host_root_sub() {
        assert_eq!(
            host_of("https://api.example.com:8080/a/b?q=1"),
            "api.example.com"
        );
        assert_eq!(host_of("http://user@1.2.3.4:80/"), "1.2.3.4");
        assert_eq!(host_of("EXAMPLE.com"), "example.com");
        assert_eq!(host_of("[2001:db8::1]:443/x"), "2001:db8::1");
        assert_eq!(root_of("api.staging.example.com"), "example.com");
        assert_eq!(root_of("example.com"), "example.com");
        assert_eq!(root_of("1.2.3.4"), "1.2.3.4");
        assert!(is_subdomain("api.example.com", "example.com"));
        assert!(!is_subdomain("example.com", "example.com"));
        assert!(!is_subdomain("1.2.3.4", "1.2.3.4"));
    }

    #[test]
    fn template_path_matching() {
        // concrete inject/scan URL links back to the templated operation
        assert!(path_matches_template(
            "127.0.0.1:7005/users/v1/1",
            "127.0.0.1:7005/users/v1/{username}"
        ));
        assert!(path_matches_template(
            "api.x.com/orders/42/items/7",
            "api.x.com/orders/{oid}/items/{iid}"
        ));
        // exact literal path still matches
        assert!(path_matches_template("x.com/a/b", "x.com/a/b"));
        // literal segment mismatch fails
        assert!(!path_matches_template(
            "127.0.0.1:7005/books/v1/1",
            "127.0.0.1:7005/users/v1/{username}"
        ));
        // differing segment count fails
        assert!(!path_matches_template("x.com/a/b/c", "x.com/a/{id}"));
    }

    #[test]
    fn parse_port_and_params() {
        assert_eq!(port_of("example.com:8443/x"), "8443");
        assert_eq!(port_of("https://example.com:8443"), "8443");
        assert_eq!(port_of("example.com/x"), "");
        assert_eq!(
            query_params("https://x.com/y?a=1&b=2&=skip"),
            vec!["a", "b"]
        );
        assert!(query_params("https://x.com/y").is_empty());
        // A bare token must not become a param asset. The tracer drops these now, but an
        // older installed build does not, and whatever posts a trace is not trusted to
        // have redacted it.
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123signature";
        assert!(query_params(&format!("https://x.com/y?{jwt}")).is_empty());
        assert_eq!(
            query_params(&format!("https://x.com/y?page=2&{jwt}&debug")),
            vec!["page", "debug"]
        );
        // Base64 padding splits into a key and a `=` value, which is not a named param.
        assert!(query_params("https://x.com/y?YWJjZA==").is_empty());
        // A short flag is real request shape and survives; a keyed param always does.
        assert_eq!(query_params("https://x.com/y?debug"), vec!["debug"]);
        assert_eq!(
            query_params("https://x.com/y?Signature=AbCdEf%2Bgh%2F123%3D"),
            vec!["Signature"]
        );
        assert!(query_params("https://x.com/y?d41d8cd98f00b204e9800998ecf8427e").is_empty());
    }

    #[test]
    fn id_normalization() {
        assert!(is_id_like("123"));
        assert!(is_id_like("550e8400-e29b-41d4-a716-446655440000"));
        assert!(is_id_like("deadbeefdeadbeef"));
        assert!(!is_id_like("v1"));
        assert!(!is_id_like("users"));
        assert_eq!(
            normalize_endpoint("https://api.example.com/api/v1/users/123?x=1"),
            "api.example.com/api/v1/users/{id}"
        );
        assert_eq!(
            normalize_endpoint("https://api.example.com/"),
            "api.example.com/"
        );
        assert_eq!(normalize_endpoint("http://h.com/a/b"), "h.com/a/b");
    }
}

//! Personal data returned to callers who never authenticated.
//!
//! The authz engine answers "can identity B read identity A's object". It works
//! by comparing identities, so it is structurally blind to the case where there
//! is no identity at all: an endpoint that answers everyone the same way, and
//! what it answers is somebody's record. VAmPI's `/users/v1/{username}` is the
//! textbook shape - it returns a named user's email to an unauthenticated
//! caller - and every authorization oracle correctly stays silent, because no
//! authorization boundary is being crossed. There isn't one.
//!
//! That is OWASP API3 (excessive data exposure) sitting underneath API1, and it
//! is a real and frequently paid bug: a public endpoint enumerable by id that
//! hands back user records.
//!
//! Two oracles here, both requiring proof rather than shape:
//!
//!   1. **Credentials in an unauthenticated response.** A `password`,
//!      `password_hash`, `ssn` or `credit_card` field in a body served to
//!      nobody in particular is not a judgement call.
//!   2. **Two identifiers, two people.** Fetch the endpoint with the
//!      identifier it came with, then with a different identifier the crawl
//!      actually observed at the same position. If both answer with the same
//!      personal fields carrying *different* values, then the endpoint serves
//!      arbitrary users' records to an unauthenticated caller. One record could
//!      be the caller's own; two different ones cannot be.
//!
//! Deliberately not flagged: a single record with no credential field (it could
//! be a public profile the site intends to publish), any response when the scan
//! is running with credentials (the claim is about unauthenticated access), and
//! anything that is not JSON.

use cfx_finding::Finding;
use serde_json::{Map, Value};
use transport::Client;

/// Fields that make a body somebody's personal record.
const PERSONAL: &[&str] = &[
    "email",
    "e_mail",
    "mail",
    "phone",
    "phone_number",
    "mobile",
    "address",
    "street",
    "postcode",
    "zip",
    "dob",
    "date_of_birth",
    "birthdate",
    "first_name",
    "last_name",
    "full_name",
    "given_name",
    "family_name",
];

/// Fields that are a finding on their own, in any unauthenticated response.
const SECRET: &[&str] = &[
    "password",
    "passwd",
    "password_hash",
    "pwd_hash",
    "hashed_password",
    "ssn",
    "social_security",
    "credit_card",
    "card_number",
    "cvv",
    "national_id",
    "passport_number",
];

fn norm(k: &str) -> String {
    k.to_lowercase().replace(['-', ' '], "_")
}

/// Every (field, value) pair anywhere in the document whose name is in `names`.
/// Walks nested objects and arrays, because the interesting bodies are almost
/// always `{"users": [ ... ]}` rather than one flat record.
fn collect(v: &Value, names: &[&str], out: &mut Vec<(String, String)>, depth: usize) {
    if depth > 6 || out.len() > 200 {
        return;
    }
    match v {
        Value::Object(map) => {
            for (k, val) in map {
                let nk = norm(k);
                if names.iter().any(|n| nk == *n) {
                    if let Some(s) = scalar(val) {
                        if !s.is_empty() {
                            out.push((nk.clone(), s));
                        }
                    }
                }
                collect(val, names, out, depth + 1);
            }
        }
        Value::Array(items) => {
            for it in items.iter().take(50) {
                collect(it, names, out, depth + 1);
            }
        }
        _ => {}
    }
}

fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn parse(body: &str) -> Option<Value> {
    // A body big enough to be a data dump is still worth reading; one that is
    // not JSON at all is not our business.
    if body.len() > 2_000_000 {
        return None;
    }
    serde_json::from_str::<Value>(body).ok()
}

/// Fields shared by both bodies whose values differ: the same record shape
/// filled in for two different people.
fn differing(a: &[(String, String)], b: &[(String, String)]) -> Vec<String> {
    let index = |pairs: &[(String, String)]| {
        let mut m: Map<String, Value> = Map::new();
        for (k, v) in pairs {
            m.entry(k.clone()).or_insert(Value::String(v.clone()));
        }
        m
    };
    let (ia, ib) = (index(a), index(b));
    ia.iter()
        .filter(|(k, va)| ib.get(*k).map(|vb| vb != *va).unwrap_or(false))
        .map(|(k, _)| k.clone())
        .collect()
}

/// Replace path segment `idx` with `value`.
fn with_segment(url: &str, idx: usize, value: &str) -> Option<String> {
    let (scheme_host, rest) = url.split_once("://").map(|(s, r)| {
        let cut = r.find('/').unwrap_or(r.len());
        (format!("{s}://{}", &r[..cut]), r[cut..].to_string())
    })?;
    let (path, query) = match rest.split_once('?') {
        Some((p, q)) => (p.to_string(), format!("?{q}")),
        None => (rest, String::new()),
    };
    let mut segs: Vec<String> = path.split('/').map(|s| s.to_string()).collect();
    if idx >= segs.len() {
        return None;
    }
    segs[idx] = value.to_string();
    Some(format!("{scheme_host}{}{query}", segs.join("/")))
}

/// A neighbouring identifier to compare against, when the corpus offered none.
///
/// A declared path parameter tells us the position varies without telling us a
/// second value. For a numeric id the neighbour is obvious and is exactly how
/// this bug gets exploited - iterate the id - so `7` gets `8` and `6` tried
/// against it. For anything else we do not guess: inventing a username would
/// only produce a 404, and a 404 is not evidence of anything.
fn neighbours(value: &str) -> Vec<String> {
    match value.parse::<i64>() {
        Ok(n) => [n + 1, n - 1]
            .iter()
            .filter(|x| **x >= 0)
            .map(|x| x.to_string())
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Field names whose values are identifiers a caller can put back in a path.
const ID_FIELDS: &[&str] = &[
    "id", "uuid", "guid", "slug", "username", "user", "name", "code", "key", "handle", "login",
];

/// Ask the collection endpoint which identifiers actually exist.
///
/// A path parameter declared by a spec arrives filled with a made-up sample:
/// VAmPI's `/users/v1/{username}` reaches us as `/users/v1/1`, which is nobody,
/// so the endpoint answers with no record and there is nothing to compare. That
/// is not the endpoint being safe, it is us asking for a user that does not
/// exist.
///
/// A human tests this by listing the collection first and then reading two of
/// the records it names, so that is what this does: drop the identifier segment,
/// GET the collection, and harvest the values of id-ish fields. A wrong guess
/// costs one request and proves nothing, which is why the oracle downstream
/// still requires two different people's data before it reports.
async fn learn_identifiers(client: &Client, url: &str, idx: usize) -> Vec<String> {
    let Some(head) = url.split_once("://") else {
        return Vec::new();
    };
    let (scheme, rest) = head;
    let path_and_q = rest;
    let path = path_and_q.split('?').next().unwrap_or("");
    let segs: Vec<&str> = path.split('/').collect();
    if idx == 0 || idx >= segs.len() {
        return Vec::new();
    }
    let collection = format!("{scheme}://{}", segs[..idx].join("/"));
    let Some(resp) = crate::probe::send(client, "GET", &collection, None).await else {
        return Vec::new();
    };
    if !(200..300).contains(&resp.status) {
        return Vec::new();
    }
    let Some(doc) = parse(&resp.body) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    collect(&doc, ID_FIELDS, &mut found, 0);
    let mut out: Vec<String> = Vec::new();
    for (_k, v) in found {
        // Only values that can sit in a path segment: no spaces, no slashes,
        // nothing long enough to be prose rather than a key.
        if v.is_empty() || v.len() > 64 || v.contains([' ', '/', '?', '#']) {
            continue;
        }
        if !out.contains(&v) {
            out.push(v);
        }
        if out.len() >= 4 {
            break;
        }
    }
    out
}

/// `alternatives` is (segment index, other values observed at that position).
/// `declared` are positions the endpoint itself says are parameters, used when
/// the corpus has only ever seen one value there.
pub async fn probe(
    client: &Client,
    method: &str,
    url: &str,
    alternatives: &[(usize, Vec<String>)],
    declared: &[usize],
) -> Option<Value> {
    if !method.eq_ignore_ascii_case("GET") {
        return None; // reading somebody's record is a GET
    }
    let first = crate::probe::send(client, "GET", url, None).await?;
    // A 404 here is not an answer about the endpoint, it is an answer about the
    // identifier we were handed. A spec-declared path parameter arrives filled
    // with a made-up sample, so the common case is that we asked for a record
    // that does not exist. Fall through to the collection lookup rather than
    // treating "no such user" as "no such problem".
    let doc = if (200..300).contains(&first.status) {
        parse(&first.body).unwrap_or(Value::Null)
    } else {
        Value::Null
    };

    // --- 1. credentials in a response served to nobody in particular --------
    let mut secrets = Vec::new();
    collect(&doc, SECRET, &mut secrets, 0);
    if !secrets.is_empty() {
        let mut names: Vec<String> = secrets.iter().map(|(k, _)| k.clone()).collect();
        names.sort();
        names.dedup();
        return Some(
            Finding::new(
                "cortex-exposure",
                "excessive_exposure",
                "Credentials returned to an unauthenticated request",
                "critical",
                url,
            )
            .method("GET")
            .location("endpoint")
            .describe(format!(
                "This endpoint answered a request carrying no credentials with a body containing \
                 {} ({} occurrence(s)). Whatever else is true of the authorization model, secrets \
                 of this kind must never appear in a response, and an endpoint that serves them to \
                 anonymous callers is a disclosure of every account it covers (OWASP API3: \
                 Excessive Data Exposure).",
                names.join(", "),
                secrets.len()
            ))
            .build(),
        );
    }

    // --- 2. two identifiers, two people -------------------------------------
    let mut personal = Vec::new();
    collect(&doc, PERSONAL, &mut personal, 0);

    // Nothing personal came back. Before concluding the endpoint is safe, check
    // whether we simply asked for a record that does not exist: a spec-declared
    // path parameter arrives filled with a made-up sample. If the collection
    // names real identifiers, read two of them and compare those instead.
    if personal.is_empty() {
        let mut positions: Vec<usize> = declared.to_vec();
        positions.extend(alternatives.iter().map(|(i, _)| *i));
        positions.sort_unstable();
        positions.dedup();
        for idx in positions {
            let ids = learn_identifiers(client, url, idx).await;
            if ids.len() < 2 {
                continue;
            }
            for pair in ids.windows(2) {
                let (Some(ua), Some(ub)) = (
                    with_segment(url, idx, &pair[0]),
                    with_segment(url, idx, &pair[1]),
                ) else {
                    continue;
                };
                let (Some(ra), Some(rb)) = (
                    crate::probe::send(client, "GET", &ua, None).await,
                    crate::probe::send(client, "GET", &ub, None).await,
                ) else {
                    continue;
                };
                if !(200..300).contains(&ra.status) || !(200..300).contains(&rb.status) {
                    continue;
                }
                let (Some(da), Some(db)) = (parse(&ra.body), parse(&rb.body)) else {
                    continue;
                };
                let (mut pa, mut pb) = (Vec::new(), Vec::new());
                collect(&da, PERSONAL, &mut pa, 0);
                collect(&db, PERSONAL, &mut pb, 0);
                let changed = differing(&pa, &pb);
                if changed.is_empty() {
                    continue;
                }
                let mut fields = changed;
                fields.sort();
                return Some(
                    Finding::new(
                        "cortex-exposure",
                        "excessive_exposure",
                        "Personal records readable without authentication, by identifier",
                        "high",
                        &ua,
                    )
                    .method("GET")
                    .location("path")
                    .describe(format!(
                        "The collection at this path names its own members, and reading two of \
                         them with no credentials returned two different people's records: {} \
                         differ between `{ua}` and `{ub}`. One record could belong to the caller; \
                         two cannot. Anyone who can list the collection can then read every \
                         record in it (OWASP API3: Excessive Data Exposure).",
                        fields.join(", ")
                    ))
                    .build(),
                );
            }
        }
        return None;
    }

    // Observed values first; a declared position with no observed alternative
    // falls back to numeric neighbours.
    let mut candidates: Vec<(usize, Vec<String>)> = alternatives.to_vec();
    let segs: Vec<&str> = url
        .split_once("://")
        .map(|(_, r)| r)
        .unwrap_or(url)
        .split('?')
        .next()
        .unwrap_or("")
        .split('/')
        .collect();
    for d in declared {
        if candidates.iter().any(|(i, _)| i == d) {
            continue;
        }
        // `segs` here counts the host as element 0, which is how the path
        // indices elsewhere are numbered.
        if let Some(cur) = segs.get(*d) {
            let n = neighbours(cur);
            if !n.is_empty() {
                candidates.push((*d, n));
            }
        }
    }

    for (idx, values) in &candidates {
        for alt in values {
            let Some(other) = with_segment(url, *idx, alt) else {
                continue;
            };
            if other == url {
                continue;
            }
            let Some(second) = crate::probe::send(client, "GET", &other, None).await else {
                continue;
            };
            if !(200..300).contains(&second.status) {
                continue;
            }
            let Some(doc2) = parse(&second.body) else {
                continue;
            };
            let mut personal2 = Vec::new();
            collect(&doc2, PERSONAL, &mut personal2, 0);
            let changed = differing(&personal, &personal2);
            if changed.is_empty() {
                continue;
            }
            let mut fields = changed.clone();
            fields.sort();
            return Some(
                Finding::new(
                    "cortex-exposure",
                    "excessive_exposure",
                    "Personal records readable without authentication, by identifier",
                    "high",
                    url,
                )
                .method("GET")
                .location("path")
                .describe(format!(
                    "Two different identifiers at the same position in this path returned two \
                     different people's records to requests carrying no credentials: {} differ \
                     between `{url}` and `{other}`. One record could belong to the caller; two \
                     cannot. The endpoint serves arbitrary users' data to anonymous callers, so \
                     the whole user table is enumerable by anyone who can guess or iterate the \
                     identifier (OWASP API3: Excessive Data Exposure, and API1 where the data is \
                     meant to be owner-scoped).",
                    fields.join(", ")
                ))
                .build(),
            );
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn finds_personal_fields_inside_nested_documents() {
        let doc = json!({"users": [
            {"username": "a", "email": "a@x.test"},
            {"username": "b", "email": "b@x.test"}
        ]});
        let mut out = Vec::new();
        collect(&doc, PERSONAL, &mut out, 0);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn a_config_document_is_not_personal_data() {
        // mirage's bait: config-shaped, fictional, and nobody's record.
        let doc = json!({"env": "production", "api_key": "not-a-real-key-0000",
                         "database_url": "postgres://user:pass@localhost/none",
                         "debug": false});
        let mut personal = Vec::new();
        collect(&doc, PERSONAL, &mut personal, 0);
        let mut secret = Vec::new();
        collect(&doc, SECRET, &mut secret, 0);
        assert!(personal.is_empty());
        assert!(
            secret.is_empty(),
            "api_key/database_url are not per-person secrets"
        );
    }

    #[test]
    fn the_same_record_twice_is_not_two_people() {
        let a = vec![("email".to_string(), "a@x.test".to_string())];
        let same = a.clone();
        assert!(differing(&a, &same).is_empty());
        let b = vec![("email".to_string(), "b@x.test".to_string())];
        assert_eq!(differing(&a, &b), vec!["email".to_string()]);
    }

    #[test]
    fn a_numeric_id_has_neighbours_and_a_username_does_not() {
        assert_eq!(neighbours("7"), vec!["8".to_string(), "6".to_string()]);
        assert_eq!(neighbours("0"), vec!["1".to_string()]);
        assert!(neighbours("alice").is_empty());
    }

    #[test]
    fn segment_substitution_keeps_the_query() {
        assert_eq!(
            with_segment("http://h/users/v1/name1?x=1", 3, "name2").unwrap(),
            "http://h/users/v1/name2?x=1"
        );
        assert!(with_segment("http://h/users", 9, "z").is_none());
    }
}

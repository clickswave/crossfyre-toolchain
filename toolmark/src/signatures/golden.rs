//! The saved responses in `tests/responses`, each run through [`detect`], give exactly
//! the detections `tests/responses/expected.json` holds for it: the names, categories,
//! versions, CPEs, confidence and evidence, in the order they are reported.
//!
//! A saved response is an HTTP/1.1 response as text, after any number of lines starting
//! with `#` that say where it came from. Those named `lab-` are pages the lab's targets
//! served; the rest are written from what each product is publicly known to send.
//!
//! A change meant to alter what is detected writes the file again with
//! `TOOLMARK_GOLDEN=write cargo test -p toolmark golden`, and the diff of
//! `expected.json` is then the change to review.

use super::{Detection, RULES, detect, extract_meta_generator, first_n, header_val};
use serde_json::{Value, json};
use std::collections::BTreeMap;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/responses");

/// A saved response, as a fingerprint hands it to [`detect`].
struct Saved {
    headers: Vec<(String, String)>,
    cookies: Vec<String>,
    body: String,
}

fn parse(name: &str, text: &str) -> Saved {
    let mut rest = text;
    while rest.starts_with('#') {
        rest = rest.split_once('\n').map_or("", |(_, after)| after);
    }
    let (head, body) = rest
        .split_once("\n\n")
        .unwrap_or_else(|| panic!("{name}: no empty line after the headers"));
    let mut lines = head.lines();
    let status = lines.next().unwrap_or_default();
    assert!(status.starts_with("HTTP/1.1 "), "{name}: {status}");
    let mut headers = Vec::new();
    let mut cookies = Vec::new();
    for line in lines {
        let (header, value) = line
            .split_once(':')
            .unwrap_or_else(|| panic!("{name}: not a header: {line}"));
        let (header, value) = (header.to_lowercase(), value.trim().to_string());
        if header == "set-cookie" {
            cookies.push(value.clone());
        }
        headers.push((header, value));
    }
    Saved {
        headers,
        cookies,
        body: body.to_string(),
    }
}

/// Every saved response, by file name.
fn saved() -> BTreeMap<String, Saved> {
    let mut out = BTreeMap::new();
    for entry in std::fs::read_dir(DIR).expect("tests/responses") {
        let path = entry.expect("entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("http") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("name")
            .to_string();
        let text = String::from_utf8_lossy(&std::fs::read(&path).expect("read")).into_owned();
        out.insert(name.clone(), parse(&name, &text));
    }
    out
}

fn as_json(d: &Detection) -> Value {
    json!({
        "name": d.name,
        "category": d.category,
        "version": d.version,
        "cpe": d.cpe,
        "confidence": d.confidence,
        "evidence": d.evidence,
    })
}

fn detections(s: &Saved) -> Vec<Detection> {
    detect(&s.headers, &s.cookies, &s.body)
}

#[test]
fn each_saved_response_gives_the_detections_it_gave_before() {
    let got: BTreeMap<String, Value> = saved()
        .iter()
        .map(|(name, s)| {
            let found: Vec<Value> = detections(s).iter().map(as_json).collect();
            (name.clone(), Value::Array(found))
        })
        .collect();
    let path = format!("{DIR}/expected.json");
    if std::env::var("TOOLMARK_GOLDEN").as_deref() == Ok("write") {
        let text = serde_json::to_string_pretty(&got).expect("json");
        std::fs::write(&path, text + "\n").expect("write expected.json");
        return;
    }
    let want: BTreeMap<String, Value> =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("expected.json"))
            .expect("expected.json parses");
    let mut names: Vec<&String> = want.keys().chain(got.keys()).collect();
    names.sort();
    names.dedup();
    let changed: Vec<String> = names
        .into_iter()
        .filter(|name| want.get(*name) != got.get(*name))
        .map(|name| {
            format!(
                "{name}\n  expected: {}\n  detected: {}",
                want.get(name)
                    .map_or("nothing saved".into(), Value::to_string),
                got.get(name)
                    .map_or("no such response".into(), Value::to_string),
            )
        })
        .collect();
    assert!(
        changed.is_empty(),
        "{} saved response(s) no longer give what they did:\n{}",
        changed.len(),
        changed.join("\n")
    );
}

/// The string a rule's version pattern is run over, as [`detect`] builds it.
fn version_text(s: &Saved) -> String {
    let server = header_val(&s.headers, "server").unwrap_or_default();
    let powered = header_val(&s.headers, "x-powered-by").unwrap_or_default();
    let generator = extract_meta_generator(&s.body).unwrap_or_default();
    let head = first_n(&s.body, 60_000);
    format!("{server} {powered} {generator} {head}")
}

/// Each rule is found by at least one saved response in its own right, not only
/// implied, and every group of every version pattern gives the version in at least one.
#[test]
fn the_saved_responses_exercise_every_rule_and_version_pattern() {
    let saved = saved();
    let found: Vec<(Detection, String)> = saved
        .values()
        .flat_map(|s| {
            let text = version_text(s);
            detections(s).into_iter().map(move |d| (d, text.clone()))
        })
        .collect();
    let mut missing = Vec::new();
    for rule in RULES.iter() {
        let direct: Vec<&(Detection, String)> = found
            .iter()
            .filter(|(d, _)| d.name == rule.name && d.category != "Implied")
            .collect();
        if direct.is_empty() {
            missing.push(format!("{}: found by no saved response", rule.name));
            continue;
        }
        let Some(re) = &rule.version else { continue };
        for group in 1..re.captures_len() {
            let gives = direct.iter().any(|(d, text)| {
                d.version.is_some()
                    && re
                        .captures(text)
                        .and_then(|c| (1..c.len()).find(|i| c.get(*i).is_some()))
                        == Some(group)
            });
            if !gives {
                missing.push(format!(
                    "{}: no saved response gives a version through group {group} of {re}",
                    rule.name
                ));
            }
        }
    }
    assert!(missing.is_empty(), "{}", missing.join("\n"));
}

//! The saved responses in `tests/responses`, each run through the shipped signatures at
//! the rendered tier, give exactly the detections `tests/responses/expected.json` holds
//! for them: the names, categories, versions, CPEs, confidence, evidence and candidates,
//! in the order they are reported.
//!
//! A saved response is an HTTP/1.1 response as text, after any number of lines starting
//! with `#` that say where it came from. `name.http` is a host's landing page. What the
//! same host answers for other paths, when a signature asks, is in `name/`: one file per
//! path, named after it with each `/` written `%2F` (`feed%2F.http` is `/feed/`), and
//! `_otherwise.http` for any path not saved there. A host with no `_otherwise.http`
//! answers a path it does not have with a 404. Those named `lab-` are pages the lab's
//! targets served; the rest are written from what each product is publicly known to send.
//!
//! A `name.pem` beside `name.http` is the certificate the landing page came with, which
//! makes it a page that came over TLS; without one it came over plain HTTP. A
//! `name.rendered.html` is the page as a browser built it; a page without one was not
//! rendered, and answers as it would at the standard tier.
//!
//! A `name.banner` is a service rather than a page: after its `#` lines, the name a probe
//! identified it by on one line, and what the probe read from it on the next.
//!
//! A change meant to alter what is detected writes the file again with
//! `TOOLMARK_GOLDEN=write cargo test -p toolmark golden`, and the diff of
//! `expected.json` is then the change to review.

use super::{Answer, Answered, Detection, Host, RENDERED, Signatures, ask};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::Path;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/responses");

/// One saved response.
struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    cookies: Vec<String>,
    body: String,
}

/// A saved page: the landing page, what its host answers for other paths, and the
/// certificate it came with, DER encoded, when it came over TLS.
struct Page {
    landing: Response,
    paths: BTreeMap<String, Response>,
    otherwise: Option<Response>,
    certificate: Option<Vec<u8>>,
    rendered: Option<String>,
}

impl Page {
    /// What this host answers when `path` is asked.
    fn answer(&self, path: &str) -> Answered {
        match self.paths.get(path).or(self.otherwise.as_ref()) {
            Some(r) => Answered::new(r.status, false, r.body.as_bytes()),
            None => Answered::new(404, false, b""),
        }
    }
}

/// A saved host: a page, or a service and what its probe read from it.
enum Saved {
    Page(Page),
    Service { name: String, text: String },
}

impl Saved {
    /// This host after the shipped signatures have asked it what they need.
    async fn host(&self) -> Host<'_> {
        let page = match self {
            Saved::Page(page) => page,
            Saved::Service { name, text } => {
                return Host::service(Signatures::shipped(), name, text);
            }
        };
        let r = &page.landing;
        let mut host = Host::new(
            Signatures::shipped(),
            "http://saved.test/",
            &r.headers,
            &r.cookies,
            &r.body,
            RENDERED,
        );
        match &page.certificate {
            Some(der) => host.certificate(der),
            None => host.no_tls(),
        }
        if let Some(dom) = &page.rendered {
            host.rendered(dom.clone());
        }
        ask(&mut host, |path, _| std::future::ready(page.answer(&path))).await;
        host
    }
}

fn parse(name: &str, text: &str) -> Response {
    let mut rest = text;
    while rest.starts_with('#') {
        rest = rest.split_once('\n').map_or("", |(_, after)| after);
    }
    let (head, body) = rest
        .split_once("\n\n")
        .unwrap_or_else(|| panic!("{name}: no empty line after the headers"));
    let mut lines = head.lines();
    let status_line = lines.next().unwrap_or_default();
    let status = status_line
        .strip_prefix("HTTP/1.1 ")
        .and_then(|s| s.split(' ').next())
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("{name}: {status_line}"));
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
    Response {
        status,
        headers,
        cookies,
        body: body.to_string(),
    }
}

fn read(path: &Path) -> Response {
    let name = path.display().to_string();
    parse(
        &name,
        &String::from_utf8_lossy(&std::fs::read(path).expect("read")),
    )
}

/// A saved service: the name it was identified by, and what was read from it.
fn service(path: &Path) -> Saved {
    let text = std::fs::read_to_string(path).expect("read");
    let mut lines = text.lines().filter(|line| !line.starts_with('#'));
    let mut next = || {
        lines
            .next()
            .unwrap_or_else(|| panic!("{}: a name and a line read", path.display()))
            .to_string()
    };
    Saved::Service {
        name: next(),
        text: next(),
    }
}

/// Every saved host, by the file name of its landing page.
fn saved() -> BTreeMap<String, Saved> {
    let mut out = BTreeMap::new();
    for entry in std::fs::read_dir(DIR).expect("tests/responses") {
        let path = entry.expect("entry").path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("name")
            .to_string();
        match path.extension().and_then(|e| e.to_str()) {
            Some("http") => {}
            Some("banner") => {
                out.insert(name, service(&path));
                continue;
            }
            _ => continue,
        }
        let pem = path.with_extension("pem");
        let rendered = path.with_extension("rendered.html");
        let mut host = Page {
            landing: read(&path),
            paths: BTreeMap::new(),
            otherwise: None,
            certificate: pem.exists().then(|| {
                use x509_cert::der::{DecodePem, Encode};
                let text = std::fs::read_to_string(&pem).expect("read");
                x509_cert::Certificate::from_pem(text.as_bytes())
                    .and_then(|c| c.to_der())
                    .unwrap_or_else(|e| panic!("{}: {e}", pem.display()))
            }),
            rendered: rendered
                .exists()
                .then(|| std::fs::read_to_string(&rendered).expect("read")),
        };
        let more = path.with_extension("");
        if more.is_dir() {
            for entry in std::fs::read_dir(&more).expect("a saved host's paths") {
                let file = entry.expect("entry").path();
                let stem = file
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .expect("name")
                    .to_string();
                if stem == "_otherwise" {
                    host.otherwise = Some(read(&file));
                } else {
                    host.paths
                        .insert(format!("/{}", stem.replace("%2F", "/")), read(&file));
                }
            }
        }
        out.insert(name, Saved::Page(host));
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
        "candidates": d.candidates,
        "version_range": d.version_range.as_ref().map(|r| json!({
            "since": r.since.as_ref().map(ToString::to_string),
            "until": r.until.as_ref().map(ToString::to_string),
        })),
        "distro": d.distro,
    })
}

#[tokio::test]
async fn each_saved_response_gives_the_detections_it_gave_before() {
    let mut got: BTreeMap<String, Value> = BTreeMap::new();
    for (name, saved) in &saved() {
        let found: Vec<Value> = saved
            .host()
            .await
            .detections()
            .iter()
            .map(as_json)
            .collect();
        got.insert(name.clone(), Value::Array(found));
    }
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

/// Each leaf is exercised by a saved host: every `detect` leaf, under a `none` too, is
/// present in one, every `version` leaf reads a version, or for a range is present, and
/// every `distro` leaf reads a tag, in one its signature is present in. Every group of a
/// version pattern gives the version in one, through a leaf that carries the pattern.
#[tokio::test]
async fn the_saved_responses_exercise_every_leaf() {
    let saved = saved();
    let mut hosts = Vec::new();
    for s in saved.values() {
        hosts.push(s.host().await);
    }
    let mut missing = Vec::new();
    for signature in &Signatures::shipped().list {
        let Some(detect) = &signature.detect else {
            continue;
        };
        let mut leaves = Vec::new();
        detect.leaves(&mut leaves);
        for (n, leaf) in leaves.iter().enumerate() {
            if !hosts.iter().any(|h| h.answer(leaf).0 == Answer::Present) {
                missing.push(format!(
                    "{}: detect leaf {} is present on no saved host",
                    signature.id,
                    n + 1
                ));
            }
        }
        let found_in: Vec<&Host> = hosts
            .iter()
            .filter(|h| h.eval(detect, None).answer == Answer::Present)
            .collect();
        let mut groups: BTreeMap<&str, Vec<bool>> = BTreeMap::new();
        for (n, leaf) in signature.version.iter().enumerate() {
            // A leaf that gives a range is exercised by being present where its product is.
            if leaf.range.is_some() {
                if !found_in.iter().any(|h| h.answer(leaf).0 == Answer::Present) {
                    missing.push(format!(
                        "{}: version leaf {} is present on no saved host its product is",
                        signature.id,
                        n + 1
                    ));
                }
                continue;
            }
            let Some(regex) = &leaf.regex else {
                continue;
            };
            let given: Vec<usize> = found_in
                .iter()
                .filter_map(|h| h.version_of(leaf).map(|(group, _)| group))
                .collect();
            if given.is_empty() {
                missing.push(format!(
                    "{}: version leaf {} reads a version on no saved host",
                    signature.id,
                    n + 1
                ));
            }
            let seen = groups
                .entry(regex.as_str())
                .or_insert_with(|| vec![false; regex.captures_len()]);
            for group in given {
                seen[group] = true;
            }
        }
        for (n, leaf) in signature.distro.iter().enumerate() {
            if !found_in.iter().any(|h| h.version_of(leaf).is_some()) {
                missing.push(format!(
                    "{}: distro leaf {} reads a tag on no saved host its product is",
                    signature.id,
                    n + 1
                ));
            }
        }
        for (pattern, seen) in groups {
            for group in (1..seen.len()).filter(|g| !seen[*g]) {
                missing.push(format!(
                    "{}: no saved host gives a version through group {group} of {pattern}",
                    signature.id
                ));
            }
        }
    }
    assert!(missing.is_empty(), "{}", missing.join("\n"));
}

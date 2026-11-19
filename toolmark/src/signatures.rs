//! Web technology signatures, and the WAF and CDN tells read passively.
//!
//! A signature is a file in toolmark/signatures, compiled into the binary: the product it
//! names, the evidence that shows it, where its version is read, what it implies, and the
//! signature it refines. Each is written by hand from public knowledge of the product, so
//! no third-party dataset is compiled in.
//!
//! Each piece of evidence, a leaf, answers present, absent or unknown, and `all`, `any`
//! and `none` combine the answers. What the landing page shows is passive. A `path` leaf
//! is one more request to the host, made from the standard tier up and only when its
//! answer could still change one (see [`Host::next_path`] and [`ask`]).

mod files;
mod load;

use regex::Regex;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::LazyLock;

/// One technology found.
pub struct Detection {
    pub name: String,
    pub category: String,
    pub version: Option<String>,
    pub cpe: String,
    pub confidence: u8,
    pub evidence: Vec<String>,
    /// The products that refine this one and could not be told apart from it, because
    /// the evidence that would decide went unanswered.
    pub candidates: Vec<String>,
}

/// How much of the body an `html` leaf reads.
const HTML_READ: usize = 60_000;

/// The depth tier from which a scan asks a host for more than its landing page.
pub const STANDARD: u8 = 2;

/// The most requests made of one host for its paths in a scan, the two that learn its
/// not-found page included.
pub const MAX_PATHS: usize = 20;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Answer {
    Present,
    Absent,
    Unknown,
}

/// What a response shows, for a leaf to look at.
enum Source {
    /// The value of the first header with this name, which is lower case.
    Header(String),
    /// The name of each cookie the response sets.
    Cookie,
    /// The content of the first meta tag with this name, anywhere in the body.
    Meta(String),
    /// The first [`HTML_READ`] bytes of the body.
    Html,
    /// What the host answers for this path, asked for on its own.
    Path(String),
}

impl Source {
    /// The depth tier a scan needs for this evidence to be looked at.
    fn tier(&self) -> u8 {
        match self {
            Source::Path(_) => STANDARD,
            _ => 0,
        }
    }
}

/// One piece of evidence a signature looks for, or reads a version from.
struct Leaf {
    source: Source,
    /// What the evidence has to match. Only a `path` can do without, when the path being
    /// there is the evidence.
    regex: Option<Regex>,
    /// What it adds to the confidence when it is present.
    confidence: u32,
}

/// How a signature's evidence combines.
enum Node {
    Leaf(Leaf),
    All(Vec<Node>),
    Any(Vec<Node>),
    None(Vec<Node>),
}

impl Node {
    /// Every leaf under this node, in order.
    fn leaves<'a>(&'a self, out: &mut Vec<&'a Leaf>) {
        match self {
            Node::Leaf(leaf) => out.push(leaf),
            Node::All(children) | Node::Any(children) | Node::None(children) => {
                for child in children {
                    child.leaves(out);
                }
            }
        }
    }

    /// Every leaf under this node that counts for the product rather than against it,
    /// which is every one not under a `none`.
    fn supporting<'a>(&'a self, out: &mut Vec<&'a Leaf>) {
        match self {
            Node::Leaf(leaf) => out.push(leaf),
            Node::All(children) | Node::Any(children) => {
                for child in children {
                    child.supporting(out);
                }
            }
            Node::None(_) => {}
        }
    }
}

/// One signature file.
struct Signature {
    id: String,
    name: String,
    category: String,
    /// Vendor, product and target software, for the CPE.
    cpe: Option<(String, String, Option<String>)>,
    /// The ids of the signatures for what this one implies.
    implies: Vec<String>,
    /// The id of the signature this one replaces when both are present.
    refines: Option<String>,
    /// None for a product known only from what implies it.
    detect: Option<Node>,
    /// The first of these that reads a version gives it.
    version: Vec<Leaf>,
}

impl Signature {
    /// The CPE 2.3 name for this product at `version`, or empty when the file names no
    /// vendor and product.
    fn cpe(&self, version: Option<&str>) -> String {
        let Some((vendor, product, target)) = &self.cpe else {
            return String::new();
        };
        format!(
            "cpe:2.3:a:{}:{}:{}:*:*:*:*:{}:*:*",
            cpe_value(vendor),
            cpe_value(product),
            version.map_or("*".into(), cpe_value),
            target.as_deref().map_or("*".into(), cpe_value),
        )
    }
}

/// A value as a CPE 2.3 formatted string writes it: anything but a letter, a digit, a
/// period, a hyphen or an underscore escaped with a backslash.
fn cpe_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// A set of signatures, in the order their detections are reported.
pub struct Signatures {
    list: Vec<Signature>,
    /// A finder for each meta tag name a leaf reads.
    metas: BTreeMap<String, MetaFinder>,
}

/// The signatures compiled into toolmark. A file that does not load is left out, and why
/// is printed.
static SHIPPED: LazyLock<Signatures> = LazyLock::new(|| {
    let (signatures, skipped) = load::load(files::FILES);
    for why in skipped {
        eprintln!("[toolmark] a signature file was skipped: {why}");
    }
    signatures
});

impl Signatures {
    /// The signatures compiled into toolmark.
    pub fn shipped() -> &'static Self {
        &SHIPPED
    }

    fn by_id(&self, id: &str) -> Option<&Signature> {
        self.list.iter().find(|s| s.id == id)
    }
}

/// Signatures from `files`, for a test elsewhere in toolmark, and why any were left out.
#[cfg(test)]
pub fn load_for_tests(files: &[(&str, &str)]) -> (Signatures, Vec<String>) {
    load::load(files)
}

/// Finds the content of a meta tag by its name, whichever of the two attributes comes first.
struct MetaFinder {
    name_first: Regex,
    content_first: Regex,
}

impl MetaFinder {
    fn new(name: &str) -> Self {
        let name = regex::escape(name);
        let re = |pattern: String| Regex::new(&pattern).expect("a meta pattern");
        Self {
            name_first: re(format!(
                r#"(?is)<meta[^>]+name\s*=\s*["']{name}["'][^>]+content\s*=\s*["']([^"']+)["']"#
            )),
            content_first: re(format!(
                r#"(?is)<meta[^>]+content\s*=\s*["']([^"']+)["'][^>]+name\s*=\s*["']{name}["']"#
            )),
        }
    }

    fn content(&self, body: &str) -> Option<String> {
        self.name_first
            .captures(body)
            .or_else(|| self.content_first.captures(body))
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
    }
}

/// What one request for a path was answered with.
pub struct Answered {
    /// None when nothing came back: a timeout, or a connection that failed.
    pub status: Option<u16>,
    /// The request ended somewhere other than the path, through a redirect.
    pub moved: bool,
    pub body: String,
}

impl Answered {
    /// No answer at all.
    pub fn none() -> Self {
        Self {
            status: None,
            moved: false,
            body: String::new(),
        }
    }
}

/// What a host answers for a path that does not exist, learned from two random paths.
enum NotFound {
    /// Not asked yet.
    Unasked,
    /// A 404 or a 410.
    Honest,
    /// The same page with this status, whatever the path. The body is kept with the
    /// path taken out of it.
    Page { status: u16, body: String },
    /// Answers that differ, so no answer to another path can be shown to be this one.
    Unusable,
}

impl NotFound {
    fn learn(a: (&str, &Answered), b: (&str, &Answered)) -> Self {
        let usable = |x: &Answered| !x.moved && x.status.is_some();
        if !usable(a.1) || !usable(b.1) {
            return NotFound::Unusable;
        }
        match (a.1.status, b.1.status) {
            (Some(x), Some(y)) if gone(x) && gone(y) => NotFound::Honest,
            (Some(x), Some(y)) if x == y && (200..300).contains(&x) => {
                let body = without(&a.1.body, a.0);
                if body == without(&b.1.body, b.0) {
                    NotFound::Page { status: x, body }
                } else {
                    NotFound::Unusable
                }
            }
            _ => NotFound::Unusable,
        }
    }

    /// Whether `answered`, the answer for `path`, is this host's not-found page.
    fn is(&self, path: &str, status: u16, body: &str) -> bool {
        matches!(self, NotFound::Page { status: s, body: b } if *s == status && *b == without(body, path))
    }
}

fn gone(status: u16) -> bool {
    status == 404 || status == 410
}

/// `body` with `path` taken out wherever it appears, with and without its leading slash,
/// as a not-found page that names the path it was asked for does.
fn without(body: &str, path: &str) -> String {
    let body = body.replace(path, "");
    match path.strip_prefix('/').filter(|bare| bare.len() >= 4) {
        Some(bare) => body.replace(bare, ""),
        None => body,
    }
}

/// A path no host has: sixteen hex digits, different every time.
fn random_path() -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default(),
    );
    format!("/{:016x}", hasher.finish())
}

/// The landing page as the leaves look at it.
struct Page<'a> {
    headers: &'a [(String, String)],
    /// The name of each cookie set, in order.
    cookies: Vec<&'a str>,
    html: &'a str,
    /// The content of each meta tag a leaf reads, by name.
    metas: BTreeMap<&'a str, Option<String>>,
}

impl<'a> Page<'a> {
    /// What a leaf reading `source` matches against on the landing page, other than a
    /// cookie or a path.
    fn text(&self, source: &Source) -> Option<&str> {
        match source {
            Source::Header(name) => self
                .headers
                .iter()
                .find(|(header, _)| header == name)
                .map(|(_, value)| value.as_str()),
            Source::Meta(name) => self.metas.get(name.as_str()).and_then(|c| c.as_deref()),
            Source::Html => Some(self.html),
            Source::Cookie | Source::Path(_) => None,
        }
    }

    /// The evidence for a passive leaf on this page, when it is there.
    fn found(&self, leaf: &Leaf) -> Option<String> {
        let regex = leaf.regex.as_ref()?;
        if let Source::Cookie = leaf.source {
            return self
                .cookies
                .iter()
                .find(|name| regex.is_match(name))
                .map(|name| format!("cookie {name}"));
        }
        let text = self.text(&leaf.source)?;
        if !regex.is_match(text) {
            return None;
        }
        Some(match &leaf.source {
            Source::Header(name) => format!("header {name}: {}", truncate(text, 80)),
            Source::Meta(name) => format!("meta {name}: {}", truncate(text, 80)),
            _ => "body pattern".to_string(),
        })
    }
}

/// How a node answered, and when present, what its leaves add.
struct Outcome {
    answer: Answer,
    confidence: u32,
    evidence: Vec<String>,
}

impl Outcome {
    fn bare(answer: Answer) -> Self {
        Self {
            answer,
            confidence: 0,
            evidence: Vec::new(),
        }
    }

    fn present(of: Vec<Outcome>) -> Self {
        Self {
            answer: Answer::Present,
            confidence: of.iter().map(|o| o.confidence).sum(),
            evidence: of.into_iter().flat_map(|o| o.evidence).collect(),
        }
    }
}

/// What one host has shown: its landing page, and its answers for the paths asked of it.
pub struct Host<'a> {
    signatures: &'a Signatures,
    page: Page<'a>,
    /// The depth tier of the scan.
    tier: u8,
    /// How each leaf on the landing page answered, by the leaf's address.
    passive: HashMap<usize, (Answer, Option<String>)>,
    not_found: NotFound,
    asked: BTreeMap<String, Answered>,
}

impl<'a> Host<'a> {
    pub fn new(
        signatures: &'a Signatures,
        headers: &'a [(String, String)],
        cookies: &'a [String],
        body: &'a str,
        tier: u8,
    ) -> Self {
        let page = Page {
            headers,
            cookies: cookies
                .iter()
                .map(|c| c.split(['=', ';']).next().unwrap_or_default().trim())
                .collect(),
            html: first_n(body, HTML_READ),
            metas: signatures
                .metas
                .iter()
                .map(|(name, finder)| (name.as_str(), finder.content(body)))
                .collect(),
        };
        let mut leaves = Vec::new();
        for signature in &signatures.list {
            if let Some(detect) = &signature.detect {
                detect.leaves(&mut leaves);
            }
        }
        let passive = leaves
            .into_iter()
            .filter(|l| !matches!(l.source, Source::Path(_)))
            .map(|l| {
                let found = page.found(l);
                let answer = if found.is_some() {
                    Answer::Present
                } else {
                    Answer::Absent
                };
                (std::ptr::from_ref(l) as usize, (answer, found))
            })
            .collect();
        Self {
            signatures,
            page,
            tier,
            passive,
            not_found: NotFound::Unasked,
            asked: BTreeMap::new(),
        }
    }

    /// How `leaf` answers here, and its evidence when present. A leaf above the scan's
    /// tier is unknown, as is a path not asked yet.
    fn answer(&self, leaf: &Leaf) -> (Answer, Option<String>) {
        if leaf.source.tier() > self.tier {
            return (Answer::Unknown, None);
        }
        let Source::Path(path) = &leaf.source else {
            return self
                .passive
                .get(&(std::ptr::from_ref(leaf) as usize))
                .cloned()
                .unwrap_or_else(|| match self.page.found(leaf) {
                    Some(e) => (Answer::Present, Some(e)),
                    None => (Answer::Absent, None),
                });
        };
        let Some(answered) = self.asked.get(path) else {
            return (Answer::Unknown, None);
        };
        match answered.status {
            Some(status) if gone(status) && !answered.moved => (Answer::Absent, None),
            Some(status) if (200..300).contains(&status) && !answered.moved => {
                if self.not_found.is(path, status, &answered.body) {
                    return (Answer::Absent, None);
                }
                let evidence = Some(format!("path {path}: {status}"));
                match &leaf.regex {
                    Some(regex) if regex.is_match(&answered.body) => (Answer::Present, evidence),
                    Some(_) => (Answer::Unknown, None),
                    None if matches!(self.not_found, NotFound::Honest | NotFound::Page { .. }) => {
                        (Answer::Present, evidence)
                    }
                    None => (Answer::Unknown, None),
                }
            }
            _ => (Answer::Unknown, None),
        }
    }

    /// How `node` answers, with `forced` taken as the answer of that one leaf.
    fn eval(&self, node: &Node, forced: Option<(&Leaf, Answer)>) -> Outcome {
        let children =
            |list: &[Node]| -> Vec<Outcome> { list.iter().map(|c| self.eval(c, forced)).collect() };
        let has =
            |outcomes: &[Outcome], answer: Answer| outcomes.iter().any(|o| o.answer == answer);
        match node {
            Node::Leaf(leaf) => {
                if let Some((which, answer)) = forced
                    && std::ptr::eq(which, leaf)
                {
                    return Outcome::bare(answer);
                }
                match self.answer(leaf) {
                    (Answer::Present, evidence) => Outcome {
                        answer: Answer::Present,
                        confidence: leaf.confidence,
                        evidence: evidence.into_iter().collect(),
                    },
                    (answer, _) => Outcome::bare(answer),
                }
            }
            Node::All(list) => {
                let outcomes = children(list);
                if has(&outcomes, Answer::Absent) {
                    Outcome::bare(Answer::Absent)
                } else if has(&outcomes, Answer::Unknown) {
                    Outcome::bare(Answer::Unknown)
                } else {
                    Outcome::present(outcomes)
                }
            }
            Node::Any(list) => {
                let outcomes = children(list);
                if has(&outcomes, Answer::Present) {
                    Outcome::present(
                        outcomes
                            .into_iter()
                            .filter(|o| o.answer == Answer::Present)
                            .collect(),
                    )
                } else if has(&outcomes, Answer::Unknown) {
                    Outcome::bare(Answer::Unknown)
                } else {
                    Outcome::bare(Answer::Absent)
                }
            }
            Node::None(list) => {
                let outcomes = children(list);
                if has(&outcomes, Answer::Present) {
                    Outcome::bare(Answer::Absent)
                } else if has(&outcomes, Answer::Unknown) {
                    Outcome::bare(Answer::Unknown)
                } else {
                    Outcome::present(Vec::new())
                }
            }
        }
    }

    /// Every signature with something to detect, and how it answers here.
    fn outcomes(&self) -> Vec<(&'a Signature, Outcome)> {
        self.signatures
            .list
            .iter()
            .filter_map(|s| s.detect.as_ref().map(|d| (s, self.eval(d, None))))
            .collect()
    }

    /// What `leaf` reads its version from here, when it can be read.
    fn text(&self, leaf: &Leaf) -> Option<&str> {
        if leaf.source.tier() > self.tier {
            return None;
        }
        let Source::Path(path) = &leaf.source else {
            return self.page.text(&leaf.source);
        };
        let answered = self.asked.get(path)?;
        let status = answered
            .status
            .filter(|s| (200..300).contains(s) && !answered.moved)?;
        (!self.not_found.is(path, status, &answered.body)).then_some(answered.body.as_str())
    }

    /// The version `signature` reads here: from the first of its version leaves that
    /// matches, the first group of the pattern that takes part.
    fn version(&self, signature: &Signature) -> Option<String> {
        signature.version.iter().find_map(|leaf| {
            let captures = leaf.regex.as_ref()?.captures(self.text(leaf)?)?;
            (1..captures.len())
                .find_map(|i| captures.get(i))
                .map(|m| m.as_str().to_string())
        })
    }

    /// Whether a signature present here refines `signature`, directly or through others,
    /// which replaces it.
    fn refined(&self, signature: &Signature, outcomes: &[(&Signature, Outcome)]) -> bool {
        outcomes
            .iter()
            .filter(|(_, o)| o.answer == Answer::Present)
            .any(|(other, _)| {
                let mut base = other.refines.as_deref();
                while let Some(id) = base {
                    if id == signature.id {
                        return true;
                    }
                    base = self.signatures.by_id(id).and_then(|s| s.refines.as_deref());
                }
                false
            })
    }

    /// The signatures refining `base`, directly or through others, that are unknown here,
    /// so could not be told apart from it.
    fn candidates(&self, base: &Signature, outcomes: &[(&Signature, Outcome)]) -> Vec<String> {
        let mut out = Vec::new();
        let mut bases = VecDeque::from([base.id.as_str()]);
        while let Some(id) = bases.pop_front() {
            for (signature, outcome) in outcomes {
                if signature.refines.as_deref() == Some(id) && outcome.answer == Answer::Unknown {
                    out.push(signature.name.clone());
                    bases.push_back(signature.id.as_str());
                }
            }
        }
        out
    }

    /// What was found: each signature present and not replaced by one that refines it, in
    /// the order of the files, then what those imply and were not found themselves.
    pub fn detections(&self) -> Vec<Detection> {
        let outcomes = self.outcomes();
        let mut found: Vec<(&Signature, Detection)> = Vec::new();
        for (signature, outcome) in &outcomes {
            if outcome.answer != Answer::Present || self.refined(signature, &outcomes) {
                continue;
            }
            let version = self.version(signature);
            found.push((
                signature,
                Detection {
                    name: signature.name.clone(),
                    category: signature.category.clone(),
                    cpe: signature.cpe(version.as_deref()),
                    version,
                    confidence: outcome.confidence.min(100) as u8,
                    evidence: outcome.evidence.clone(),
                    candidates: self.candidates(signature, &outcomes),
                },
            ));
        }

        // One pass: what is only implied implies nothing further.
        let mut implied: Vec<Detection> = Vec::new();
        for (signature, detection) in &found {
            for id in &signature.implies {
                let Some(other) = self.signatures.by_id(id) else {
                    continue;
                };
                if found.iter().any(|(s, _)| s.id == other.id)
                    || implied.iter().any(|d| d.name == other.name)
                {
                    continue;
                }
                implied.push(Detection {
                    name: other.name.clone(),
                    category: "Implied".to_string(),
                    version: None,
                    cpe: String::new(),
                    confidence: 30,
                    evidence: vec![format!("implied by {}", detection.name)],
                    candidates: Vec::new(),
                });
            }
        }
        found.into_iter().map(|(_, d)| d).chain(implied).collect()
    }

    /// The next path worth asking, or none: below the standard tier, or once no answer
    /// left to ask could change what is reported.
    ///
    /// A path is worth asking when its answer could decide a signature that is unknown,
    /// or when it is where a signature that is reported without a version reads one.
    /// Version paths come first, then the paths of signatures with some evidence present
    /// already, then the rest, each in the order of the files.
    pub fn next_path(&self) -> Option<String> {
        if self.tier < STANDARD {
            return None;
        }
        let outcomes = self.outcomes();
        let (mut versions, mut supported, mut rest) = (Vec::new(), Vec::new(), Vec::new());
        for (signature, outcome) in &outcomes {
            match outcome.answer {
                Answer::Present => {
                    if self.refined(signature, &outcomes) || self.version(signature).is_some() {
                        continue;
                    }
                    versions.extend(signature.version.iter().find_map(|l| match &l.source {
                        Source::Path(path) if !self.asked.contains_key(path) => Some(path),
                        _ => None,
                    }));
                }
                Answer::Unknown => {
                    let Some(detect) = &signature.detect else {
                        continue;
                    };
                    let mut leaves = Vec::new();
                    detect.leaves(&mut leaves);
                    let deciding = leaves.into_iter().filter_map(|leaf| match &leaf.source {
                        Source::Path(path)
                            if !self.asked.contains_key(path)
                                && [Answer::Present, Answer::Absent].into_iter().any(|a| {
                                    self.eval(detect, Some((leaf, a))).answer != Answer::Unknown
                                }) =>
                        {
                            Some(path)
                        }
                        _ => None,
                    });
                    let mut support = Vec::new();
                    detect.supporting(&mut support);
                    if support.iter().any(|l| self.answer(l).0 == Answer::Present) {
                        supported.extend(deciding);
                    } else {
                        rest.extend(deciding);
                    }
                }
                Answer::Absent => {}
            }
        }
        versions
            .into_iter()
            .chain(supported)
            .chain(rest)
            .next()
            .cloned()
    }
}

/// Ask `host`, through `fetch`, for the paths its signatures still need, until none is
/// worth asking, [`MAX_PATHS`] requests have been made, the host says to slow down, or it
/// has failed three times running. The first path asked is preceded by two random ones,
/// which learn what the host answers for a path it does not have. Returns how many
/// requests were made.
pub async fn ask<F, Fut>(host: &mut Host<'_>, mut fetch: F) -> usize
where
    F: FnMut(String) -> Fut,
    Fut: std::future::Future<Output = Answered>,
{
    let mut sent = 0;
    let mut failing = 0;
    while let Some(path) = host.next_path() {
        if let NotFound::Unasked = host.not_found {
            if sent + 3 > MAX_PATHS {
                break;
            }
            let (a, b) = (random_path(), random_path());
            let first = fetch(a.clone()).await;
            let second = fetch(b.clone()).await;
            sent += 2;
            host.not_found = NotFound::learn((&a, &first), (&b, &second));
            if [&first, &second].iter().any(|x| x.status == Some(429)) {
                break;
            }
            failing = [&first, &second]
                .iter()
                .filter(|x| x.status.is_none_or(|s| s >= 500))
                .count();
            continue;
        }
        if sent >= MAX_PATHS {
            break;
        }
        let answered = fetch(path.clone()).await;
        sent += 1;
        let slow_down = answered.status == Some(429);
        let failed = answered.status.is_none_or(|s| s >= 500);
        host.asked.insert(path, answered);
        failing = if failed { failing + 1 } else { 0 };
        if slow_down || failing >= 3 {
            break;
        }
    }
    sent
}

/// Passive WAF/CDN/LB tells from headers and cookies. Returns (waf, cdn) as
/// serde values (a vendor string, or null).
pub fn waf_cdn(
    headers: &[(String, String)],
    cookies: &[String],
) -> (serde_json::Value, serde_json::Value) {
    use serde_json::Value;
    let has_h = |n: &str| header_val(headers, n).is_some();
    let hv = |n: &str| header_val(headers, n).unwrap_or_default().to_lowercase();
    let cookie_has = |needle: &str| cookies.iter().any(|c| c.to_lowercase().contains(needle));

    let mut waf: Option<&str> = None;
    let mut cdn: Option<&str> = None;

    // CDN / edge
    if has_h("cf-ray") || hv("server").contains("cloudflare") {
        cdn = Some("Cloudflare");
        if cookie_has("__cf_bm") || cookie_has("cf_clearance") || has_h("cf-mitigated") {
            waf = Some("Cloudflare");
        }
    }
    if hv("server").contains("akamaighost") || has_h("x-akamai-transformed") {
        cdn = Some("Akamai");
    }
    if has_h("x-amz-cf-id") || hv("via").contains("cloudfront") {
        cdn = Some("Amazon CloudFront");
    }
    if has_h("x-fastly-request-id")
        || hv("x-served-by").contains("cache") && hv("via").contains("varnish")
    {
        cdn.get_or_insert("Fastly");
    }

    // WAF / LB
    if has_h("x-sucuri-id") || has_h("x-sucuri-cache") {
        waf = Some("Sucuri");
    }
    if cookie_has("incap_ses") || cookie_has("visid_incap") || has_h("x-iinfo") {
        waf = Some("Imperva Incapsula");
    }
    if cookie_has("bigipserver") || cookie_has("ts01") {
        waf = waf.or(Some("F5 BIG-IP"));
    }
    if hv("server").contains("mod_security") || hv("server").contains("modsecurity") {
        waf = Some("ModSecurity");
    }

    (
        waf.map(|s| Value::String(s.to_string()))
            .unwrap_or(Value::Null),
        cdn.map(|s| Value::String(s.to_string()))
            .unwrap_or(Value::Null),
    )
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

pub fn header_val(headers: &[(String, String)], name: &str) -> Option<String> {
    let name = name.to_lowercase();
    headers
        .iter()
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.clone())
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

/// At most the first `n` bytes of `s`, ending on a character boundary.
fn first_n(s: &str, n: usize) -> &str {
    if s.len() <= n {
        return s;
    }
    let mut end = n;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod golden;

#[cfg(test)]
mod tests;

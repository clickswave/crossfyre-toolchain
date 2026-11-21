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
//! answer could still change one (see [`Host::next`] and [`ask`]).

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
    /// The products it may be, as their CPEs name them, which its CVE leads are looked up
    /// by: one for most; each a CPE splits it in; or, for a base none of whose candidates
    /// could be told apart, each candidate's.
    pub cpe_names: Vec<cfx_cve::Cpe>,
    pub confidence: u8,
    pub evidence: Vec<String>,
    /// The products that refine this one and could not be told apart from it: the
    /// evidence that would decide went unanswered, or there is none to be had.
    pub candidates: Vec<String>,
    /// Where the version lies when no exact one was read: what was found shipped from one
    /// version on, or until one.
    pub version_range: Option<Range>,
    /// The tag of the distribution that built this copy, as its banner gives it, which
    /// says it may carry fixes its version does not.
    pub distro: Option<String>,
}

/// A version as a signature writes it, numbers separated by dots, which compare as
/// numbers: 1.10 comes after 1.9.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    parts: Vec<u64>,
    written: String,
}

impl Version {
    /// `text` as a version, when it is numbers separated by dots.
    fn parse(text: &str) -> Option<Self> {
        let parts = text
            .split('.')
            .map(|p| {
                (!p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())).then(|| p.parse().ok())?
            })
            .collect::<Option<Vec<u64>>>()?;
        Some(Self {
            parts,
            written: text.to_string(),
        })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    /// By number, a missing part counting as 0, so 2.0 and 2 are the same version.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let n = self.parts.len().max(other.parts.len());
        let at = |v: &Self, i: usize| v.parts.get(i).copied().unwrap_or(0);
        (0..n)
            .map(|i| at(self, i).cmp(&at(other, i)))
            .find(|o| o.is_ne())
            .unwrap_or(std::cmp::Ordering::Equal)
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.written)
    }
}

/// Versions from `since` on and before `until`, either end open.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Range {
    pub since: Option<Version>,
    pub until: Option<Version>,
}

impl Range {
    /// What both this and `other` allow, or none when they allow nothing in common.
    fn and(&self, other: &Range) -> Option<Range> {
        let since = self.since.clone().max(other.since.clone());
        let until = match (&self.until, &other.until) {
            (Some(a), Some(b)) => Some(a.clone().min(b.clone())),
            (a, b) => a.clone().or_else(|| b.clone()),
        };
        match (&since, &until) {
            (Some(s), Some(u)) if s >= u => None,
            _ => Some(Range { since, until }),
        }
    }
}

/// How much of the body an `html` leaf reads.
const HTML_READ: usize = 60_000;

/// The depth tier from which a scan asks a host for more than its landing page.
pub const STANDARD: u8 = 2;

/// The depth tier at which a scan renders the landing page in a browser, above
/// aggressive (3), for the `rendered` leaves.
pub const RENDERED: u8 = 4;

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
    /// The cookies the response sets: present when one has a name this matches, and a
    /// value the leaf's pattern matches when it has one.
    Cookie(Regex),
    /// The content of the first meta tag with this name, anywhere in the body.
    Meta(String),
    /// The first [`HTML_READ`] bytes of the body.
    Html,
    /// The `src` of each script the landing page loads, as it is written there.
    ScriptSrc,
    /// What the host answers for this path, asked for on its own.
    Path(String),
    /// The content of the first script the landing page loads from its own host whose
    /// `src` matches this, asked for on its own.
    Script(Regex),
    /// What the host answers for a path it does not have: the first of the two random
    /// paths that learn its not-found page.
    NotFound,
    /// What a service probe read from a service of this name: the version it gave, or
    /// its greeting where it gives none apart.
    Banner(String),
    /// A part of the certificate the landing page's connection presented.
    Tls(CertPart),
    /// The landing page as a browser built it, its script run.
    Rendered,
}

/// The part of a certificate a `tls` leaf reads, as RFC 4514 writes a name.
#[derive(Clone, Copy)]
pub(crate) enum CertPart {
    Subject,
    Issuer,
}

/// What a host's landing page showed of a certificate.
enum Certificate {
    /// Not known, as for a page kept without it.
    Unread,
    /// The page came over plain HTTP.
    None,
    /// The subject and issuer of the certificate the server presented.
    Read { subject: String, issuer: String },
}

impl Source {
    /// The depth tier a scan needs for this evidence to be looked at.
    fn tier(&self) -> u8 {
        match self {
            Source::Path(_) | Source::Script(_) | Source::NotFound => STANDARD,
            Source::Rendered => RENDERED,
            _ => 0,
        }
    }

    /// Whether this evidence is read from a request of its own rather than from the
    /// landing page.
    fn asks(&self) -> bool {
        matches!(self, Source::Path(_) | Source::Script(_) | Source::NotFound)
    }
}

/// What a leaf that reads a request of its own needs: a path to ask, or an answer that
/// needs no request.
enum Request {
    Ask(String),
    Decided(Answer),
}

/// One piece of evidence a signature looks for, or reads a version from.
struct Leaf {
    source: Source,
    /// What the evidence has to match. Only a `path` can do without, when the path being
    /// there is the evidence, or a `path` or `script` that names its file by checksum.
    regex: Option<Regex>,
    /// The SHA-256 of the exact file a `path` or `script` leaf is.
    sha256: Option<[u8; 32]>,
    /// For a version leaf, where the version lies when this evidence is present, in place
    /// of a version it captures.
    range: Option<Range>,
    /// What it adds to the confidence when it is present.
    confidence: u32,
    /// For a version leaf on a path that is a gzip file, the table that names the build
    /// its header's time belongs to.
    stamp: Option<&'static Stamps>,
}

/// A table of builds by the time a gzip file shipped with them carries: a time not in
/// it gives no version.
pub(crate) struct Stamps(std::collections::HashMap<u32, String>);

/// The table `text` gives, stamp,version a line under its header and comments, or the
/// first line that is not one.
pub(crate) fn read_stamps(text: &str) -> Result<Stamps, String> {
    text.lines()
        .filter(|l| !l.starts_with('#') && *l != "stamp,version" && !l.is_empty())
        .map(|l| {
            let (stamp, build) = l
                .split_once(',')
                .ok_or_else(|| format!("{l:?} is not stamp,version"))?;
            let stamp = stamp
                .parse()
                .map_err(|_| format!("{stamp:?} is no stamp"))?;
            Ok((stamp, build.to_string()))
        })
        .collect::<Result<_, String>>()
        .map(Stamps)
}

/// The signatures in `dir`, its .yaml files, and why each left out was left out.
pub(crate) fn load_dir(dir: &std::path::Path) -> std::io::Result<(Signatures, Vec<String>)> {
    let mut texts = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) == Some("yaml") {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_string();
            texts.push((name, std::fs::read_to_string(&path)?));
        }
    }
    texts.sort();
    let files: Vec<(&str, &str)> = texts
        .iter()
        .map(|(n, t)| (n.as_str(), t.as_str()))
        .collect();
    Ok(load::load(&files))
}

/// Each table a `stamp` names, from toolmark/data.
pub(crate) fn stamps(name: &str) -> Option<&'static Stamps> {
    static NETSCALER: LazyLock<Stamps> = LazyLock::new(|| {
        read_stamps(include_str!("../data/netscaler-stamps.csv"))
            .expect("toolmark/data/netscaler-stamps.csv")
    });
    match name {
        "netscaler" => Some(&NETSCALER),
        _ => None,
    }
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
    /// What its CPE names: part, vendor, products and target software.
    cpe: Option<CpeSpec>,
    /// The ids of the signatures for what this one implies.
    implies: Vec<String>,
    /// The id of the signature this one replaces when both are present.
    refines: Option<String>,
    /// None for a product known only from what implies it, or for one that refines another
    /// and that nothing seen tells from it.
    detect: Option<Node>,
    /// The first of these that reads a version gives it.
    version: Vec<Leaf>,
    /// The first of these that reads a tag gives the distribution that built it.
    distro: Vec<Leaf>,
}

impl Signature {
    /// The CPE 2.3 name for this product at `version`, or empty when the file names no
    /// vendor and product.
    fn cpe(&self, version: Option<&str>) -> String {
        let Some(spec) = &self.cpe else {
            return String::new();
        };
        format!(
            "cpe:2.3:{}:{}:{}:{}:*:*:*:*:{}:*:*",
            cpe_value(&spec.part),
            cpe_value(&spec.vendor),
            cpe_value(&spec.products[0]),
            version.map_or("*".into(), cpe_value),
            spec.target.as_deref().map_or("*".into(), cpe_value),
        )
    }
}

/// What a signature's CPE names: its part, vendor, each product, and target software.
struct CpeSpec {
    part: String,
    vendor: String,
    products: Vec<String>,
    target: Option<String>,
}

impl Signature {
    /// The products the file names, as their CPEs name them.
    fn cpe_names(&self) -> Vec<cfx_cve::Cpe> {
        let Some(spec) = &self.cpe else {
            return Vec::new();
        };
        spec.products
            .iter()
            .map(|p| cfx_cve::Cpe::new(&spec.part, &spec.vendor, p))
            .collect()
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

    /// The products these signatures name by CPE: what CVE leads are looked up for.
    pub fn cpes(&self) -> std::collections::HashSet<cfx_cve::Cpe> {
        self.list.iter().flat_map(Signature::cpe_names).collect()
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
#[derive(Clone)]
pub struct Answered {
    /// None when nothing came back: a timeout, or a connection that failed.
    status: Option<u16>,
    /// The request ended somewhere other than the path, through a redirect.
    moved: bool,
    body: String,
    /// The SHA-256 of the body as it came, before it was read as text.
    sha256: [u8; 32],
    /// The time a gzip file's header gives, when the body is one.
    gzip_stamp: Option<u32>,
}

impl Answered {
    /// An answer with `status` and `body`, which ended somewhere other than the path
    /// asked when `moved`.
    pub fn new(status: u16, moved: bool, body: &[u8]) -> Self {
        use sha2::Digest;
        Self {
            status: Some(status),
            moved,
            body: String::from_utf8_lossy(body).into_owned(),
            sha256: sha2::Sha256::digest(body).into(),
            gzip_stamp: match body {
                [0x1f, 0x8b, 0x08, _, a, b, c, d, ..] => {
                    Some(u32::from_le_bytes([*a, *b, *c, *d])).filter(|&t| t != 0)
                }
                _ => None,
            },
        }
    }

    /// No answer at all.
    pub fn none() -> Self {
        Self {
            status: None,
            moved: false,
            body: String::new(),
            sha256: [0; 32],
            gzip_stamp: None,
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

/// Finds the `src` of each script element.
static SCRIPT_SRC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)<script\b[^>]*?\bsrc\s*=\s*["']([^"']+)["']"#).expect("a script pattern")
});

/// The landing page as the leaves look at it.
struct Page<'a> {
    headers: &'a [(String, String)],
    /// The name and value of each cookie set, in order.
    cookies: Vec<(&'a str, &'a str)>,
    html: &'a str,
    /// The content of each meta tag a leaf reads, by name.
    metas: BTreeMap<&'a str, Option<String>>,
    /// The `src` of each script, in the order the page loads them.
    scripts: Vec<&'a str>,
    /// For a service rather than a page: its name, and what its probe read from it.
    banner: Option<(&'a str, &'a str)>,
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
            Source::Tls(_) | Source::Rendered => None,
            Source::Banner(name) => self
                .banner
                .filter(|(service, _)| *service == name.as_str())
                .map(|(_, text)| text),
            Source::Cookie(_)
            | Source::ScriptSrc
            | Source::Path(_)
            | Source::Script(_)
            | Source::NotFound => None,
        }
    }

    /// The evidence for a passive leaf on this page, when it is there.
    fn found(&self, leaf: &Leaf) -> Option<String> {
        if let Source::Cookie(names) = &leaf.source {
            return self
                .cookies
                .iter()
                .find(|(name, value)| {
                    names.is_match(name) && leaf.regex.as_ref().is_none_or(|r| r.is_match(value))
                })
                .map(|(name, _)| format!("cookie {name}"));
        }
        let regex = leaf.regex.as_ref()?;
        if let Source::ScriptSrc = leaf.source {
            return self
                .scripts
                .iter()
                .find(|src| regex.is_match(src))
                .map(|src| format!("script src {}", truncate(src, 120)));
        }
        let text = self.text(&leaf.source)?;
        if !regex.is_match(text) {
            return None;
        }
        Some(match &leaf.source {
            Source::Header(name) => format!("header {name}: {}", truncate(text, 80)),
            Source::Meta(name) => format!("meta {name}: {}", truncate(text, 80)),
            Source::Banner(name) => format!("{name} banner: {}", truncate(text, 80)),
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
    /// Where the landing page came from, which a script's `src` is read against.
    base: Option<transport::Url>,
    /// The depth tier of the scan.
    tier: u8,
    /// How each leaf on the landing page answered, by the leaf's address.
    passive: HashMap<usize, (Answer, Option<String>)>,
    not_found: NotFound,
    /// What the host answered for the first random path, once asked.
    not_found_page: Option<Answered>,
    asked: BTreeMap<String, Answered>,
    certificate: Certificate,
    /// The landing page as a browser built it, once one has.
    rendered: Option<String>,
}

/// What a host is asked next.
#[derive(Debug, PartialEq, Eq)]
pub enum Next {
    /// The two random paths that learn its not-found page.
    NotFound,
    /// This path.
    Path(String),
}

impl<'a> Host<'a> {
    /// The host whose landing page, at `url`, answered with `headers`, `cookies` and
    /// `body`, scanned at depth tier `tier`.
    pub fn new(
        signatures: &'a Signatures,
        url: &str,
        headers: &'a [(String, String)],
        cookies: &'a [String],
        body: &'a str,
        tier: u8,
    ) -> Self {
        let page = Page {
            headers,
            cookies: cookies
                .iter()
                .map(|c| {
                    let pair = c.split(';').next().unwrap_or_default();
                    let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
                    (name.trim(), value.trim())
                })
                .collect(),
            html: first_n(body, HTML_READ),
            metas: signatures
                .metas
                .iter()
                .map(|(name, finder)| (name.as_str(), finder.content(body)))
                .collect(),
            scripts: SCRIPT_SRC
                .captures_iter(body)
                .filter_map(|c| c.get(1))
                .map(|m| m.as_str())
                .collect(),
            banner: None,
        };
        Self::of(signatures, page, url, tier)
    }

    /// A service a probe identified as `service`, which `text` is what it read from: the
    /// version the service gave, or its greeting. It has no page, and nothing is asked
    /// of it.
    pub fn service(signatures: &'a Signatures, service: &'a str, text: &'a str) -> Self {
        let page = Page {
            headers: &[],
            cookies: Vec::new(),
            html: "",
            metas: BTreeMap::new(),
            scripts: Vec::new(),
            banner: Some((service, text)),
        };
        Self::of(signatures, page, "", 0)
    }

    fn of(signatures: &'a Signatures, page: Page<'a>, url: &str, tier: u8) -> Self {
        let mut leaves = Vec::new();
        for signature in &signatures.list {
            if let Some(detect) = &signature.detect {
                detect.leaves(&mut leaves);
            }
        }
        let passive = leaves
            .into_iter()
            .filter(|l| !l.source.asks() && !matches!(l.source, Source::Tls(_) | Source::Rendered))
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
            base: transport::Url::parse(url).ok(),
            tier,
            passive,
            not_found: NotFound::Unasked,
            not_found_page: None,
            asked: BTreeMap::new(),
            certificate: Certificate::Unread,
            rendered: None,
        }
    }

    /// The certificate the landing page's server presented, DER encoded. One that does
    /// not parse leaves the certificate unknown.
    pub fn certificate(&mut self, der: &[u8]) {
        use x509_cert::der::Decode;
        if let Ok(cert) = x509_cert::Certificate::from_der(der) {
            self.certificate = Certificate::Read {
                subject: cert.tbs_certificate.subject.to_string(),
                issuer: cert.tbs_certificate.issuer.to_string(),
            };
        }
    }

    /// The landing page as a browser built it, its script run, for the `rendered`
    /// leaves. Until a browser has rendered it, they are unknown.
    pub fn rendered(&mut self, dom: String) {
        self.rendered = Some(dom);
    }

    /// The landing page came over plain HTTP, so there was no certificate.
    pub fn no_tls(&mut self) {
        self.certificate = Certificate::None;
    }

    /// The part of the certificate `part` names, when one was read.
    fn certificate_part(&self, part: CertPart) -> Option<&str> {
        match (&self.certificate, part) {
            (Certificate::Read { subject, .. }, CertPart::Subject) => Some(subject),
            (Certificate::Read { issuer, .. }, CertPart::Issuer) => Some(issuer),
            _ => None,
        }
    }

    /// Pages kept from an earlier scan of this host, given to it as its answers: what it
    /// said for the random paths that learn its not-found page, and for the paths asked by
    /// signatures, each with the path it was asked at. Nothing is asked of the host.
    pub fn remember(&mut self, not_found: Vec<(String, Answered)>, paths: Vec<(String, Answered)>) {
        let mut pages = not_found.into_iter();
        match (pages.next(), pages.next()) {
            (Some(a), Some(b)) => {
                self.not_found = NotFound::learn((&a.0, &a.1), (&b.0, &b.1));
                self.not_found_page = Some(a.1);
            }
            (Some(a), None) => {
                self.not_found = NotFound::Unusable;
                self.not_found_page = Some(a.1);
            }
            _ => {}
        }
        self.asked.extend(paths);
    }

    /// What `leaf`, when it reads a request of its own, needs here. A `script` leaf whose
    /// script the landing page does not load is absent with no request, and one whose
    /// script comes from another host is unknown, as that host is not the one scanned.
    fn request(&self, leaf: &Leaf) -> Option<Request> {
        match &leaf.source {
            Source::Path(path) => Some(Request::Ask(path.clone())),
            Source::Script(src) => {
                let Some(written) = self.page.scripts.iter().find(|s| src.is_match(s)) else {
                    return Some(Request::Decided(Answer::Absent));
                };
                let base = self.base.as_ref()?;
                let url = base.join(written).ok()?;
                let same = url.scheme() == base.scheme()
                    && url.host_str() == base.host_str()
                    && url.port_or_known_default() == base.port_or_known_default();
                if !same {
                    return Some(Request::Decided(Answer::Unknown));
                }
                Some(Request::Ask(match url.query() {
                    Some(query) => format!("{}?{query}", url.path()),
                    None => url.path().to_string(),
                }))
            }
            _ => None,
        }
    }

    /// The host's not-found page and its status, when it can be read: a 404, a 410 or a
    /// 2xx, not moved. A 401, 403, 429 or 5xx for a random path is the host refusing or
    /// failing, not its not-found page, and proves nothing.
    fn not_found_page(&self) -> Option<(u16, &str)> {
        let page = self.not_found_page.as_ref()?;
        let status = page
            .status
            .filter(|s| !page.moved && (gone(*s) || (200..300).contains(s)))?;
        Some((status, page.body.as_str()))
    }

    /// How `leaf` answers here, and its evidence when present. A leaf above the scan's
    /// tier is unknown, as is a request not made yet.
    fn answer(&self, leaf: &Leaf) -> (Answer, Option<String>) {
        if leaf.source.tier() > self.tier {
            return (Answer::Unknown, None);
        }
        if let Source::Rendered = leaf.source {
            let Some(dom) = &self.rendered else {
                return (Answer::Unknown, None);
            };
            return match &leaf.regex {
                Some(regex) if regex.is_match(dom) => {
                    (Answer::Present, Some("rendered page pattern".to_string()))
                }
                _ => (Answer::Absent, None),
            };
        }
        if let Source::Tls(part) = leaf.source {
            if let Certificate::Unread = self.certificate {
                return (Answer::Unknown, None);
            }
            return match (self.certificate_part(part), &leaf.regex) {
                (Some(text), Some(regex)) if regex.is_match(text) => {
                    let name = match part {
                        CertPart::Subject => "subject",
                        CertPart::Issuer => "issuer",
                    };
                    (
                        Answer::Present,
                        Some(format!("certificate {name}: {}", truncate(text, 80))),
                    )
                }
                _ => (Answer::Absent, None),
            };
        }
        if let Source::NotFound = leaf.source {
            let Some((status, body)) = self.not_found_page() else {
                return (Answer::Unknown, None);
            };
            return match &leaf.regex {
                Some(regex) if regex.is_match(body) => {
                    (Answer::Present, Some(format!("not-found page: {status}")))
                }
                _ => (Answer::Absent, None),
            };
        }
        let path = match self.request(leaf) {
            None if !leaf.source.asks() => {
                return self
                    .passive
                    .get(&(std::ptr::from_ref(leaf) as usize))
                    .cloned()
                    .unwrap_or_else(|| match self.page.found(leaf) {
                        Some(e) => (Answer::Present, Some(e)),
                        None => (Answer::Absent, None),
                    });
            }
            None => return (Answer::Unknown, None),
            Some(Request::Decided(answer)) => return (answer, None),
            Some(Request::Ask(path)) => path,
        };
        let Some(answered) = self.asked.get(&path) else {
            return (Answer::Unknown, None);
        };
        match answered.status {
            Some(status) if gone(status) && !answered.moved => (Answer::Absent, None),
            Some(status) if (200..300).contains(&status) && !answered.moved => {
                if self.not_found.is(&path, status, &answered.body) {
                    return (Answer::Absent, None);
                }
                let kind = if let Source::Script(_) = leaf.source {
                    "script"
                } else {
                    "path"
                };
                let evidence = Some(format!("{kind} {path}: {status}"));
                if let Some(sha256) = &leaf.sha256 {
                    return if *sha256 == answered.sha256 {
                        (Answer::Present, evidence)
                    } else {
                        (Answer::Unknown, None)
                    };
                }
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

    /// What `leaf` reads its version from here, when it can be read: one text, or for a
    /// `script_src` leaf the `src` of each script.
    fn texts(&self, leaf: &Leaf) -> Vec<&str> {
        if leaf.source.tier() > self.tier {
            return Vec::new();
        }
        if let Source::ScriptSrc = leaf.source {
            return self.page.scripts.clone();
        }
        if let Source::Tls(part) = leaf.source {
            return self.certificate_part(part).into_iter().collect();
        }
        if let Source::Rendered = leaf.source {
            return self.rendered.as_deref().into_iter().collect();
        }
        if let Source::NotFound = leaf.source {
            return self
                .not_found_page()
                .map(|(_, body)| body)
                .into_iter()
                .collect();
        }
        if !matches!(self.request(leaf), Some(Request::Ask(_))) {
            return self.page.text(&leaf.source).into_iter().collect();
        }
        self.answered(leaf)
            .map(|a| a.body.as_str())
            .into_iter()
            .collect()
    }

    /// What the host answered for the path `leaf` asks for, when it answered with the
    /// file and not its not-found page.
    fn answered(&self, leaf: &Leaf) -> Option<&Answered> {
        let Some(Request::Ask(path)) = self.request(leaf) else {
            return None;
        };
        let answered = self.asked.get(&path)?;
        match answered.status {
            Some(s) if (200..300).contains(&s) && !answered.moved => {
                (!self.not_found.is(&path, s, &answered.body)).then_some(answered)
            }
            _ => None,
        }
    }

    /// The group of `leaf`'s pattern that reads a version here, and what it reads: the
    /// first group that takes part in the first match.
    fn version_of(&self, leaf: &Leaf) -> Option<(usize, String)> {
        if let Some(table) = leaf.stamp {
            let stamp = self.answered(leaf)?.gzip_stamp?;
            return table.0.get(&stamp).map(|build| (1, build.clone()));
        }
        let regex = leaf.regex.as_ref()?;
        self.texts(leaf).into_iter().find_map(|text| {
            let captures = regex.captures(text)?;
            (1..captures.len()).find_map(|i| captures.get(i).map(|m| (i, m.as_str().to_string())))
        })
    }

    /// The version `signature` reads here: from the first of its version leaves that
    /// reads one.
    fn version(&self, signature: &Signature) -> Option<String> {
        signature
            .version
            .iter()
            .filter(|leaf| leaf.range.is_none())
            .find_map(|leaf| self.version_of(leaf).map(|(_, v)| v))
    }

    /// The distribution `signature` was built by here: from the first of its distro leaves
    /// that reads a tag.
    fn distro(&self, signature: &Signature) -> Option<String> {
        signature
            .distro
            .iter()
            .find_map(|leaf| self.version_of(leaf).map(|(_, tag)| tag))
    }

    /// Where `signature`'s version lies here, from its range leaves that are present, all
    /// of them at once. None when none is present, or when they allow no version at all.
    fn version_range(&self, signature: &Signature) -> Option<Range> {
        let mut ranges = signature
            .version
            .iter()
            .filter(|leaf| self.answer(leaf).0 == Answer::Present)
            .filter_map(|leaf| leaf.range.as_ref());
        let first = ranges.next()?.clone();
        ranges.try_fold(first, |all, range| all.and(range))
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

    /// The signatures refining `base`, directly or through others, that could not be told
    /// apart from it: those unknown here, and those with nothing to detect, which nothing
    /// seen ever tells apart.
    fn candidates(&self, base: &Signature, outcomes: &[(&Signature, Outcome)]) -> Vec<String> {
        let mut out = Vec::new();
        let mut bases = VecDeque::from([base.id.as_str()]);
        while let Some(id) = bases.pop_front() {
            for signature in &self.signatures.list {
                if signature.refines.as_deref() != Some(id) {
                    continue;
                }
                let unknown = signature.detect.is_none()
                    || outcomes
                        .iter()
                        .any(|(s, o)| s.id == signature.id && o.answer == Answer::Unknown);
                if unknown {
                    out.push(signature.name.clone());
                    bases.push_back(signature.id.as_str());
                }
            }
        }
        out
    }

    /// The products `signature`, found, may be by their CPEs: its own, or with none, those
    /// of the candidates that could not be told apart from it.
    fn cpe_names(
        &self,
        signature: &Signature,
        outcomes: &[(&Signature, Outcome)],
    ) -> Vec<cfx_cve::Cpe> {
        let own = signature.cpe_names();
        if !own.is_empty() {
            return own;
        }
        self.candidates(signature, outcomes)
            .iter()
            .filter_map(|name| self.signatures.list.iter().find(|s| &s.name == name))
            .flat_map(Signature::cpe_names)
            .collect()
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
            let version_range = version
                .is_none()
                .then(|| self.version_range(signature))
                .flatten();
            found.push((
                signature,
                Detection {
                    name: signature.name.clone(),
                    category: signature.category.clone(),
                    cpe: signature.cpe(version.as_deref()),
                    cpe_names: self.cpe_names(signature, &outcomes),
                    version,
                    confidence: outcome.confidence.min(100) as u8,
                    evidence: outcome.evidence.clone(),
                    candidates: self.candidates(signature, &outcomes),
                    version_range,
                    distro: self.distro(signature),
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
                    cpe_names: Vec::new(),
                    confidence: 30,
                    evidence: vec![format!("implied by {}", detection.name)],
                    candidates: Vec::new(),
                    version_range: None,
                    distro: None,
                });
            }
        }
        found.into_iter().map(|(_, d)| d).chain(implied).collect()
    }

    /// What `leaf` would need asked here before it could answer: the not-found page, a
    /// path, or nothing, because it has its answer or no request could give one.
    fn pending(&self, leaf: &Leaf) -> Option<Next> {
        if leaf.source.tier() > self.tier {
            return None;
        }
        if let Source::NotFound = leaf.source {
            return matches!(self.not_found, NotFound::Unasked).then_some(Next::NotFound);
        }
        match self.request(leaf) {
            Some(Request::Ask(path)) if !self.asked.contains_key(&path) => Some(Next::Path(path)),
            _ => None,
        }
    }

    /// What to ask next, or nothing: below the standard tier, or once no answer left to
    /// ask could change what is reported.
    ///
    /// A request is worth making when its answer could decide a signature that is
    /// unknown, or when it is where a signature reported without a version reads one.
    /// The not-found page comes before any path. Version paths come first, then the
    /// paths of signatures with some evidence present already, then the rest, each in the
    /// order of the files.
    pub fn next(&self) -> Option<Next> {
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
                    versions.extend(signature.version.iter().find_map(|l| self.pending(l)));
                }
                Answer::Unknown => {
                    let Some(detect) = &signature.detect else {
                        continue;
                    };
                    let mut leaves = Vec::new();
                    detect.leaves(&mut leaves);
                    let deciding = leaves.into_iter().filter_map(|leaf| {
                        let next = self.pending(leaf)?;
                        [Answer::Present, Answer::Absent]
                            .into_iter()
                            .any(|a| self.eval(detect, Some((leaf, a))).answer != Answer::Unknown)
                            .then_some(next)
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
        let mut wanted = versions.into_iter().chain(supported).chain(rest).peekable();
        match (&self.not_found, wanted.peek()) {
            (_, None) => None,
            (NotFound::Unasked, Some(_)) => Some(Next::NotFound),
            _ => wanted.find(|n| matches!(n, Next::Path(_))),
        }
    }
}

/// Ask `host`, through `fetch`, for what its signatures still need, until nothing is
/// worth asking, [`MAX_PATHS`] requests have been made, the host says to slow down, or it
/// has failed three times running. Before any path, two random ones learn what the host
/// answers for a path it does not have, which is also all an error-page leaf needs.
/// Returns how many requests were made.
pub async fn ask<F, Fut>(host: &mut Host<'_>, mut fetch: F) -> usize
where
    F: FnMut(String, crate::observe::Asked) -> Fut,
    Fut: std::future::Future<Output = Answered>,
{
    let mut sent = 0;
    let mut failing = 0;
    while let Some(next) = host.next() {
        let path = match next {
            Next::NotFound => {
                if sent + 2 > MAX_PATHS {
                    break;
                }
                let (a, b) = (random_path(), random_path());
                let first = fetch(a.clone(), crate::observe::Asked::NotFound).await;
                let second = fetch(b.clone(), crate::observe::Asked::NotFound).await;
                sent += 2;
                host.not_found = NotFound::learn((&a, &first), (&b, &second));
                let refused = [&first, &second].iter().any(|x| x.status == Some(429));
                failing = [&first, &second]
                    .iter()
                    .filter(|x| x.status.is_none_or(|s| s >= 500))
                    .count();
                host.not_found_page = Some(first);
                if refused {
                    break;
                }
                continue;
            }
            Next::Path(path) => path,
        };
        if sent >= MAX_PATHS {
            break;
        }
        let answered = fetch(path.clone(), crate::observe::Asked::Path).await;
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

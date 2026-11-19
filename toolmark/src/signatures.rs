//! Web technology signatures, and the WAF and CDN tells read passively.
//!
//! A signature is a file in toolmark/signatures, compiled into the binary: the product it
//! names, the evidence that shows it, where its version can be read, and the products it
//! implies. Each is written by hand from public knowledge of the product, so no
//! third-party dataset is compiled in. Confidence is additive and capped, and a CPE is
//! built from the vendor and product a file names, as a join key for CVE matching.

mod files;

use regex::Regex;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::LazyLock;

/// One detected technology.
pub struct Detection {
    pub name: String,
    pub category: String,
    pub version: Option<String>,
    pub cpe: String,
    pub confidence: u8,
    pub evidence: Vec<String>,
}

/// How much of the body an `html` leaf reads.
const HTML_READ: usize = 60_000;

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
}

/// One piece of evidence a signature looks for, or reads a version from.
struct Leaf {
    source: Source,
    regex: Regex,
    /// What it adds to the confidence when it is there.
    confidence: u32,
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
    /// Any one of these found is the product found.
    detect: Vec<Leaf>,
    /// The first of these that reads a version gives it.
    version: Vec<Leaf>,
}

/// Every signature that loaded, in the order of [`files::FILES`].
static SIGNATURES: LazyLock<Signatures> = LazyLock::new(|| {
    let (signatures, skipped) = Signatures::load(files::FILES);
    for why in skipped {
        eprintln!("[toolmark] a signature file was skipped: {why}");
    }
    signatures
});

struct Signatures {
    list: Vec<Signature>,
    /// A finder for each meta tag name a leaf reads.
    metas: BTreeMap<String, MetaFinder>,
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileSpec {
    id: String,
    info: InfoSpec,
    #[serde(default)]
    implies: Vec<String>,
    detect: Option<DetectSpec>,
    #[serde(default)]
    version: Vec<BTreeMap<String, LeafSpec>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InfoSpec {
    name: String,
    category: String,
    metadata: Option<MetadataSpec>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MetadataSpec {
    vendor: String,
    product: String,
    target_sw: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DetectSpec {
    any: Vec<BTreeMap<String, LeafSpec>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LeafSpec {
    name: Option<String>,
    regex: Option<String>,
    confidence: Option<u32>,
}

/// A leaf from its one-key map, `{ header: { name: server, regex: ... } }`. A version
/// leaf has to capture the version, and takes no confidence.
fn leaf(entry: BTreeMap<String, LeafSpec>, version: bool) -> Result<Leaf, String> {
    let mut entries = entry.into_iter();
    let (Some((kind, spec)), None) = (entries.next(), entries.next()) else {
        return Err("a leaf is a map with one key, its kind".into());
    };
    let compile = |pattern: &str| {
        Regex::new(pattern).map_err(|e| format!("{kind} pattern {pattern:?} does not compile: {e}"))
    };
    let needs = |field: Option<String>, what: &str| {
        field.ok_or_else(|| format!("a {kind} leaf needs {what}"))
    };
    let (source, regex, confidence) = match kind.as_str() {
        "header" => {
            let name = needs(spec.name, "a name")?.to_ascii_lowercase();
            let regex = compile(&needs(spec.regex, "a regex")?)?;
            (Source::Header(name), regex, 50)
        }
        "cookie" => {
            if version {
                return Err("a cookie leaf reads no version".into());
            }
            if spec.regex.is_some() {
                return Err("a cookie leaf matches its name, and has no regex".into());
            }
            (Source::Cookie, compile(&needs(spec.name, "a name")?)?, 45)
        }
        "meta" => {
            let name = needs(spec.name, "a name")?.to_ascii_lowercase();
            let regex = compile(&needs(spec.regex, "a regex")?)?;
            (Source::Meta(name), regex, 60)
        }
        "html" => {
            if spec.name.is_some() {
                return Err("an html leaf has no name".into());
            }
            (Source::Html, compile(&needs(spec.regex, "a regex")?)?, 25)
        }
        other => return Err(format!("unknown leaf `{other}`")),
    };
    let confidence = match spec.confidence {
        Some(_) if version => return Err("a version leaf has no confidence".into()),
        Some(c) if !(1..=100).contains(&c) => {
            return Err(format!("confidence {c} is not between 1 and 100"));
        }
        Some(c) => c,
        None => confidence,
    };
    if version && regex.captures_len() < 2 {
        return Err(format!("version pattern {regex} captures nothing"));
    }
    Ok(Leaf {
        source,
        regex,
        confidence,
    })
}

impl Signature {
    /// The signature in file `file`, whose name without `.yaml` is its id.
    fn parse(file: &str, text: &str) -> Result<Self, String> {
        let spec: FileSpec = serde_yaml::from_str(text).map_err(|e| e.to_string())?;
        if Some(spec.id.as_str()) != file.strip_suffix(".yaml") {
            return Err(format!("its id is {}, not its file's name", spec.id));
        }
        if spec.info.name.trim().is_empty() || spec.info.category.trim().is_empty() {
            return Err("it needs a name and a category".into());
        }
        let detect = match spec.detect {
            Some(d) if d.any.is_empty() => return Err("detect lists nothing".into()),
            Some(d) => d
                .any
                .into_iter()
                .map(|l| leaf(l, false))
                .collect::<Result<_, _>>()?,
            None => Vec::new(),
        };
        let version = spec
            .version
            .into_iter()
            .map(|l| leaf(l, true))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            id: spec.id,
            name: spec.info.name,
            category: spec.info.category,
            cpe: spec
                .info
                .metadata
                .map(|m| (m.vendor, m.product, m.target_sw)),
            implies: spec.implies,
            detect,
            version,
        })
    }

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

impl Signatures {
    /// The signatures in `files`, in order, and why each file left out was left out: it
    /// did not parse, a pattern in it did not compile, its id was taken, or it implies a
    /// signature that is not there.
    fn load(files: &[(&str, &str)]) -> (Self, Vec<String>) {
        let mut skipped = Vec::new();
        let mut list: Vec<Signature> = Vec::new();
        for (file, text) in files {
            match Signature::parse(file, text) {
                Ok(s) if list.iter().any(|o| o.id == s.id) => {
                    skipped.push(format!("{file}: another file has the id {}", s.id));
                }
                Ok(s) => list.push(s),
                Err(e) => skipped.push(format!("{file}: {e}")),
            }
        }
        // Leaving one out can leave another implying it, so until none is left out.
        loop {
            let ids: Vec<String> = list.iter().map(|s| s.id.clone()).collect();
            let before = list.len();
            list.retain(|s| match s.implies.iter().find(|i| !ids.contains(i)) {
                Some(missing) => {
                    skipped.push(format!(
                        "{}.yaml: it implies {missing}, which is not there",
                        s.id
                    ));
                    false
                }
                None => true,
            });
            if list.len() == before {
                break;
            }
        }
        let metas = list
            .iter()
            .flat_map(|s| s.detect.iter().chain(&s.version))
            .filter_map(|l| match &l.source {
                Source::Meta(name) => Some((name.clone(), MetaFinder::new(name))),
                _ => None,
            })
            .collect();
        (Self { list, metas }, skipped)
    }

    fn by_id(&self, id: &str) -> Option<&Signature> {
        self.list.iter().find(|s| s.id == id)
    }
}

/// A response as the leaves look at it.
struct Page<'a> {
    headers: &'a [(String, String)],
    /// The name of each cookie set, in order.
    cookies: Vec<&'a str>,
    html: &'a str,
    /// The content of each meta tag a leaf reads, by name.
    metas: BTreeMap<&'a str, Option<String>>,
}

impl<'a> Page<'a> {
    fn new(
        signatures: &'a Signatures,
        headers: &'a [(String, String)],
        cookies: &'a [String],
        body: &'a str,
    ) -> Self {
        Self {
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
        }
    }

    /// What a leaf reading `source` matches against, other than a cookie.
    fn text(&self, source: &Source) -> Option<&str> {
        match source {
            Source::Header(name) => self
                .headers
                .iter()
                .find(|(header, _)| header == name)
                .map(|(_, value)| value.as_str()),
            Source::Meta(name) => self.metas.get(name.as_str()).and_then(|c| c.as_deref()),
            Source::Html => Some(self.html),
            Source::Cookie => None,
        }
    }
}

impl Leaf {
    /// The evidence for this leaf on `page`, when it is there.
    fn found(&self, page: &Page) -> Option<String> {
        if let Source::Cookie = self.source {
            return page
                .cookies
                .iter()
                .find(|name| self.regex.is_match(name))
                .map(|name| format!("cookie {name}"));
        }
        let text = page.text(&self.source)?;
        if !self.regex.is_match(text) {
            return None;
        }
        Some(match &self.source {
            Source::Header(name) => format!("header {name}: {}", truncate(text, 80)),
            Source::Meta(name) => format!("meta {name}: {}", truncate(text, 80)),
            _ => "body pattern".to_string(),
        })
    }

    /// The version this leaf reads on `page`: the first group of its pattern that
    /// takes part in the first match.
    fn version(&self, page: &Page) -> Option<String> {
        let captures = self.regex.captures(page.text(&self.source)?)?;
        (1..captures.len())
            .find_map(|i| captures.get(i))
            .map(|m| m.as_str().to_string())
    }
}

/// Run the signatures over a page's collected signals.
pub fn detect(headers: &[(String, String)], cookies: &[String], body: &str) -> Vec<Detection> {
    let signatures = &*SIGNATURES;
    let page = Page::new(signatures, headers, cookies, body);
    let mut found: Vec<(&Signature, Detection)> = Vec::new();
    for signature in &signatures.list {
        let leaves: Vec<(u32, String)> = signature
            .detect
            .iter()
            .filter_map(|l| l.found(&page).map(|e| (l.confidence, e)))
            .collect();
        if leaves.is_empty() {
            continue;
        }
        let version = signature.version.iter().find_map(|l| l.version(&page));
        let confidence = leaves.iter().map(|(c, _)| c).sum::<u32>().min(100) as u8;
        found.push((
            signature,
            Detection {
                name: signature.name.clone(),
                category: signature.category.clone(),
                cpe: signature.cpe(version.as_deref()),
                version,
                confidence,
                evidence: leaves.into_iter().map(|(_, e)| e).collect(),
            },
        ));
    }

    // What the products found imply, when it was not found itself. One pass: what is
    // only implied implies nothing further.
    let mut implied: Vec<Detection> = Vec::new();
    for (signature, detection) in &found {
        for id in &signature.implies {
            let Some(other) = signatures.by_id(id) else {
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
            });
        }
    }
    found.into_iter().map(|(_, d)| d).chain(implied).collect()
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
mod tests {
    use super::*;

    /// The files in toolmark/signatures are the ones files.rs includes, both ways, so a
    /// file added to the folder and not to the list fails here rather than never being
    /// compiled in. Each entry is named after the file it includes, and every file loads.
    #[test]
    fn the_compiled_set_is_the_signatures_folder() {
        use std::collections::BTreeSet;
        let root = env!("CARGO_MANIFEST_DIR");
        let on_disk: BTreeSet<String> = std::fs::read_dir(format!("{root}/signatures"))
            .expect("toolmark/signatures")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        let source = std::fs::read_to_string(format!("{root}/src/signatures/files.rs"))
            .expect("src/signatures/files.rs");
        let included: Vec<String> =
            Regex::new(r#"include_str!\(\s*"\.\./\.\./signatures/([^"]+)"\s*\)"#)
                .expect("pattern")
                .captures_iter(&source)
                .map(|c| c[1].to_string())
                .collect();
        let listed: BTreeSet<String> = included.iter().cloned().collect();
        assert_eq!(listed.len(), included.len(), "a file is included twice");
        let unlisted: Vec<&String> = on_disk.difference(&listed).collect();
        let gone: Vec<&String> = listed.difference(&on_disk).collect();
        assert!(
            unlisted.is_empty() && gone.is_empty(),
            "in toolmark/signatures and not in files.rs: {unlisted:?}; \
             in files.rs and not in toolmark/signatures: {gone:?}"
        );
        let names: Vec<&str> = files::FILES.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            names, included,
            "each entry is named after the file it includes"
        );
        let (signatures, skipped) = Signatures::load(files::FILES);
        assert!(skipped.is_empty(), "{skipped:#?}");
        assert_eq!(signatures.list.len(), files::FILES.len());
    }

    /// A file that does not load is left out with the reason, and the rest load. At run
    /// time the reason is printed; in the test above it fails the build.
    #[test]
    fn a_file_that_does_not_load_is_left_out_with_the_reason() {
        let good = "id: good\ninfo: { name: Good, category: CMS }\n\
                    detect: { any: [ { html: { regex: 'good' } } ] }\n";
        let files: &[(&str, &str)] = &[
            ("good.yaml", good),
            (
                "extra-key.yaml",
                "id: extra-key\ninfo: { name: X, category: CMS }\nrefines: good\n",
            ),
            (
                "unknown-leaf.yaml",
                "id: unknown-leaf\ninfo: { name: X, category: CMS }\n\
                 detect: { any: [ { title: { regex: 'x' } } ] }\n",
            ),
            (
                "bad-pattern.yaml",
                "id: bad-pattern\ninfo: { name: X, category: CMS }\n\
                 detect: { any: [ { html: { regex: '(' } } ] }\n",
            ),
            (
                "not-its-name.yaml",
                "id: something-else\ninfo: { name: X, category: CMS }\n",
            ),
            ("good.yaml", good),
            (
                "no-group.yaml",
                "id: no-group\ninfo: { name: X, category: CMS }\n\
                 version: [ { html: { regex: 'x [0-9.]+' } } ]\n",
            ),
            (
                "cookie-version.yaml",
                "id: cookie-version\ninfo: { name: X, category: CMS }\n\
                 version: [ { cookie: { name: '(x)' } } ]\n",
            ),
            (
                "version-confidence.yaml",
                "id: version-confidence\ninfo: { name: X, category: CMS }\n\
                 version: [ { html: { regex: 'x ([0-9.]+)', confidence: 10 } } ]\n",
            ),
            (
                "zero.yaml",
                "id: zero\ninfo: { name: X, category: CMS }\n\
                 detect: { any: [ { html: { regex: 'x', confidence: 0 } } ] }\n",
            ),
            (
                "implies-missing.yaml",
                "id: implies-missing\ninfo: { name: X, category: CMS }\nimplies: [nowhere]\n",
            ),
            (
                "implies-left-out.yaml",
                "id: implies-left-out\ninfo: { name: X, category: CMS }\n\
                 implies: [implies-missing]\n",
            ),
        ];
        let (signatures, skipped) = Signatures::load(files);
        let ids: Vec<&str> = signatures.list.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, ["good"]);
        let why = |file: &str| {
            skipped
                .iter()
                .filter(|s| s.starts_with(&format!("{file}: ")))
                .cloned()
                .collect::<Vec<_>>()
        };
        for (file, says) in [
            ("extra-key.yaml", "unknown field `refines`"),
            ("unknown-leaf.yaml", "unknown leaf `title`"),
            ("bad-pattern.yaml", "does not compile"),
            ("not-its-name.yaml", "its id is something-else"),
            ("good.yaml", "another file has the id good"),
            ("no-group.yaml", "captures nothing"),
            ("cookie-version.yaml", "a cookie leaf reads no version"),
            (
                "version-confidence.yaml",
                "a version leaf has no confidence",
            ),
            ("zero.yaml", "confidence 0 is not between 1 and 100"),
            ("implies-missing.yaml", "it implies nowhere"),
            ("implies-left-out.yaml", "it implies implies-missing"),
        ] {
            let reasons = why(file);
            assert!(
                reasons.len() == 1 && reasons[0].contains(says),
                "{file}: {reasons:?}, all: {skipped:#?}"
            );
        }
        assert_eq!(skipped.len(), 11, "{skipped:#?}");
    }

    #[test]
    fn a_cpe_escapes_what_its_formatted_string_escapes() {
        assert_eq!(cpe_value("joomla!"), "joomla\\!");
        assert_eq!(cpe_value("node.js"), "node.js");
        assert_eq!(cpe_value("http_server"), "http_server");
        assert_eq!(cpe_value("1.2+b3:4"), "1.2\\+b3\\:4");
    }
}

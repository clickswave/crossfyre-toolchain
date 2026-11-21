//! Reading signature files: what a file may hold, and why one is left out.

use super::{CertPart, Leaf, MetaFinder, Node, Range, Signature, Signatures, Source, Version};
use regex::Regex;
use serde::Deserialize;
use serde_yaml::Value;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileSpec {
    id: String,
    info: InfoSpec,
    #[serde(default)]
    implies: Vec<String>,
    refines: Option<String>,
    detect: Option<Value>,
    #[serde(default)]
    version: Vec<Value>,
    #[serde(default)]
    distro: Vec<Value>,
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
    /// The CPE part: `a` for an application, the default, or `o` for an operating
    /// system.
    part: Option<String>,
    vendor: String,
    /// The product, or the products the CPE dictionary splits it in.
    product: Products,
    target_sw: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Products {
    One(String),
    Several(Vec<String>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LeafSpec {
    name: Option<String>,
    regex: Option<String>,
    path: Option<String>,
    src: Option<String>,
    sha256: Option<String>,
    since: Option<String>,
    until: Option<String>,
    confidence: Option<u32>,
    /// For a version leaf on a path that is a gzip file: the table its header's time is
    /// looked up in.
    stamp: Option<String>,
}

/// The signatures in `files`, in order, and why each file left out was left out: it did
/// not parse, a pattern in it did not compile, its id was taken, or it implies or refines
/// a signature that is not there.
pub(super) fn load(files: &[(&str, &str)]) -> (Signatures, Vec<String>) {
    let mut skipped = Vec::new();
    let mut list: Vec<Signature> = Vec::new();
    for (file, text) in files {
        match parse(file, text) {
            Ok(s) if list.iter().any(|o| o.id == s.id) => {
                skipped.push(format!("{file}: another file has the id {}", s.id));
            }
            Ok(s) => list.push(s),
            Err(e) => skipped.push(format!("{file}: {e}")),
        }
    }
    // Leaving one out can leave another naming it, so until none is left out.
    loop {
        let ids: Vec<&str> = list.iter().map(|s| s.id.as_str()).collect();
        let gone: Vec<(String, String)> = list
            .iter()
            .filter_map(|s| {
                let why =
                    if let Some(missing) = s.implies.iter().find(|i| !ids.contains(&i.as_str())) {
                        format!("it implies {missing}, which is not there")
                    } else if let Some(base) = s.refines.as_deref().filter(|b| !ids.contains(b)) {
                        format!("it refines {base}, which is not there")
                    } else if refines_itself(s, &list) {
                        "what it refines comes back round to it".to_string()
                    } else {
                        return None;
                    };
                Some((s.id.clone(), why))
            })
            .collect();
        if gone.is_empty() {
            break;
        }
        list.retain(|s| !gone.iter().any(|(id, _)| *id == s.id));
        skipped.extend(
            gone.into_iter()
                .map(|(id, why)| format!("{id}.yaml: {why}")),
        );
    }
    let metas = list
        .iter()
        .flat_map(|s| {
            let mut leaves = Vec::new();
            if let Some(detect) = &s.detect {
                detect.leaves(&mut leaves);
            }
            leaves.extend(&s.version);
            leaves
        })
        .filter_map(|l| match &l.source {
            Source::Meta(name) => Some((name.clone(), MetaFinder::new(name))),
            _ => None,
        })
        .collect();
    (Signatures { list, metas }, skipped)
}

/// Whether following what `signature` refines, and what that refines, leads back to it.
fn refines_itself(signature: &Signature, list: &[Signature]) -> bool {
    let mut next = signature.refines.as_deref();
    for _ in 0..list.len() {
        let Some(id) = next else {
            return false;
        };
        if id == signature.id {
            return true;
        }
        next = list
            .iter()
            .find(|s| s.id == id)
            .and_then(|s| s.refines.as_deref());
    }
    true
}

/// The signature in file `file`, whose name without `.yaml` is its id.
fn parse(file: &str, text: &str) -> Result<Signature, String> {
    let spec: FileSpec = serde_yaml::from_str(text).map_err(|e| e.to_string())?;
    if Some(spec.id.as_str()) != file.strip_suffix(".yaml") {
        return Err(format!("its id is {}, not its file's name", spec.id));
    }
    let lawful = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-';
    if spec.id.is_empty() || !spec.id.chars().all(lawful) {
        return Err("an id is lower case letters, digits and hyphens".into());
    }
    if spec.info.name.trim().is_empty() || spec.info.category.trim().is_empty() {
        return Err("it needs a name and a category".into());
    }
    let detect = spec.detect.map(node).transpose()?;
    if detect.as_ref().is_some_and(|d| !positive(d)) {
        return Err("detect could hold with no evidence found, as a `none` alone does".into());
    }
    let version = spec
        .version
        .into_iter()
        .map(|v| {
            let (kind, value) = one_key(v)?;
            leaf(&kind, value, true)
        })
        .collect::<Result<_, String>>()?;
    let distro = spec
        .distro
        .into_iter()
        .map(|v| {
            let (kind, value) = one_key(v)?;
            let tag = leaf(&kind, value, true)?;
            match tag.range {
                Some(_) => Err("a distro leaf reads a tag, and gives no since or until".into()),
                None => Ok(tag),
            }
        })
        .collect::<Result<_, String>>()?;
    Ok(Signature {
        id: spec.id,
        name: spec.info.name,
        category: spec.info.category,
        cpe: spec.info.metadata.map(|m| super::CpeSpec {
            part: m.part.unwrap_or_else(|| "a".to_string()),
            vendor: m.vendor,
            products: match m.product {
                Products::One(product) => vec![product],
                Products::Several(products) => products,
            },
            target: m.target_sw,
        }),
        implies: spec.implies,
        refines: spec.refines,
        detect,
        version,
        distro,
    })
}

/// Whether `node` can only hold with some leaf in it found, which gives the detection its
/// evidence. A leaf can; `all` can when one child can; `any` when every child can, as any
/// one of them may be the one that holds; `none` never.
fn positive(node: &Node) -> bool {
    match node {
        Node::Leaf(_) => true,
        Node::All(children) => children.iter().any(positive),
        Node::Any(children) => children.iter().all(positive),
        Node::None(_) => false,
    }
}

/// A map with one key, the kind of leaf or group, and what that holds.
fn one_key(value: Value) -> Result<(String, Value), String> {
    let Value::Mapping(map) = value else {
        return Err("a leaf or a group is a map with one key, its kind".into());
    };
    let mut entries = map.into_iter();
    match (entries.next(), entries.next()) {
        (Some((Value::String(kind), value)), None) => Ok((kind, value)),
        _ => Err("a leaf or a group is a map with one key, its kind".into()),
    }
}

/// A group, `{ any: [...] }`, or a leaf, `{ html: { regex: ... } }`.
fn node(value: Value) -> Result<Node, String> {
    let (kind, value) = one_key(value)?;
    if !matches!(kind.as_str(), "all" | "any" | "none") {
        return leaf(&kind, value, false).map(Node::Leaf);
    }
    let Value::Sequence(items) = value else {
        return Err(format!("`{kind}` is a list"));
    };
    if items.is_empty() {
        return Err(format!("`{kind}` lists nothing"));
    }
    let children = items.into_iter().map(node).collect::<Result<Vec<_>, _>>()?;
    Ok(match kind.as_str() {
        "all" => Node::All(children),
        "any" => Node::Any(children),
        _ => Node::None(children),
    })
}

/// A leaf of kind `kind`. A version leaf has to capture the version, and takes no
/// confidence.
fn leaf(kind: &str, value: Value, version: bool) -> Result<Leaf, String> {
    enum Kind {
        Header,
        Cookie,
        Meta,
        Html,
        ScriptSrc,
        Path,
        Script,
        NotFound,
        Banner,
        Tls,
        Rendered,
    }
    let known = match kind {
        "header" => Kind::Header,
        "cookie" => Kind::Cookie,
        "meta" => Kind::Meta,
        "html" => Kind::Html,
        "script_src" => Kind::ScriptSrc,
        "path" => Kind::Path,
        "script" => Kind::Script,
        "not_found" => Kind::NotFound,
        "banner" => Kind::Banner,
        "tls" => Kind::Tls,
        "rendered" => Kind::Rendered,
        other => return Err(format!("unknown leaf `{other}`")),
    };
    let spec: LeafSpec = serde_yaml::from_value(value).map_err(|e| format!("{kind}: {e}"))?;
    let compile = |pattern: &str| {
        Regex::new(pattern).map_err(|e| format!("{kind} pattern {pattern:?} does not compile: {e}"))
    };
    let needs = |field: Option<String>, what: &str| {
        field.ok_or_else(|| format!("this {kind} leaf needs {what}"))
    };
    let refuse = |field: &Option<String>, what: &str| match field {
        Some(_) => Err(format!("this {kind} leaf has no {what}")),
        None => Ok(()),
    };
    if spec.sha256.is_some() && !matches!(known, Kind::Path | Kind::Script) {
        return Err(format!("this {kind} leaf has no sha256"));
    }
    let stamp = match &spec.stamp {
        None => None,
        Some(_) if !matches!(known, Kind::Path) || !version => {
            return Err("only a version leaf on a path reads a stamp".into());
        }
        Some(_) if spec.regex.is_some() || spec.sha256.is_some() => {
            return Err("a stamp leaf reads its version from its table, with no regex".into());
        }
        Some(name) => {
            Some(super::stamps(name).ok_or_else(|| format!("there is no stamp table {name:?}"))?)
        }
    };
    let range = match (&spec.since, &spec.until) {
        (None, None) => None,
        _ if !version => {
            return Err(format!(
                "this {kind} leaf has no since or until: only a version leaf does"
            ));
        }
        (since, until) => {
            let parse = |text: &Option<String>| {
                text.as_deref()
                    .map(|v| {
                        Version::parse(v).ok_or_else(|| {
                            format!("{v:?} is not a version, numbers separated by dots")
                        })
                    })
                    .transpose()
            };
            let range = Range {
                since: parse(since)?,
                until: parse(until)?,
            };
            if let (Some(s), Some(u)) = (&range.since, &range.until)
                && s >= u
            {
                return Err(format!("since {s} is not before until {u}"));
            }
            Some(range)
        }
    };
    if spec.sha256.is_some() && version && range.is_none() {
        return Err("a version leaf reads its version with a regex, not a sha256".into());
    }
    let sha256 = match &spec.sha256 {
        Some(_) if spec.regex.is_some() => {
            return Err(format!(
                "this {kind} leaf has a regex or a sha256, not both"
            ));
        }
        Some(hex) => {
            Some(sha256_of(hex).ok_or_else(|| format!("sha256 {hex:?} is not 64 hex digits"))?)
        }
        None => None,
    };
    let (source, regex, confidence) = match known {
        Kind::Header => {
            refuse(&spec.path, "path")?;
            refuse(&spec.src, "src")?;
            let name = needs(spec.name, "a name")?.to_ascii_lowercase();
            let regex = compile(&needs(spec.regex, "a regex")?)?;
            (Source::Header(name), Some(regex), 50)
        }
        Kind::Cookie => {
            if version && range.is_none() {
                return Err("a cookie leaf reads no version".into());
            }
            refuse(&spec.path, "path")?;
            refuse(&spec.src, "src")?;
            let name = compile(&needs(spec.name, "a name")?)?;
            let value = spec.regex.as_deref().map(compile).transpose()?;
            (Source::Cookie(name), value, 45)
        }
        Kind::Rendered => {
            refuse(&spec.name, "name")?;
            refuse(&spec.path, "path")?;
            refuse(&spec.src, "src")?;
            (
                Source::Rendered,
                Some(compile(&needs(spec.regex, "a regex")?)?),
                50,
            )
        }
        Kind::Tls => {
            refuse(&spec.path, "path")?;
            refuse(&spec.src, "src")?;
            let part = match needs(spec.name, "a name")?.as_str() {
                "subject" => CertPart::Subject,
                "issuer" => CertPart::Issuer,
                other => {
                    return Err(format!(
                        "a tls leaf reads the certificate's subject or issuer, not {other}"
                    ));
                }
            };
            let regex = compile(&needs(spec.regex, "a regex")?)?;
            (Source::Tls(part), Some(regex), 60)
        }
        Kind::Banner => {
            refuse(&spec.path, "path")?;
            refuse(&spec.src, "src")?;
            let name = needs(spec.name, "a name")?.to_ascii_lowercase();
            let regex = compile(&needs(spec.regex, "a regex")?)?;
            (Source::Banner(name), Some(regex), 60)
        }
        Kind::Meta => {
            refuse(&spec.path, "path")?;
            refuse(&spec.src, "src")?;
            let name = needs(spec.name, "a name")?.to_ascii_lowercase();
            let regex = compile(&needs(spec.regex, "a regex")?)?;
            (Source::Meta(name), Some(regex), 60)
        }
        Kind::Html => {
            refuse(&spec.name, "name")?;
            refuse(&spec.path, "path")?;
            refuse(&spec.src, "src")?;
            (
                Source::Html,
                Some(compile(&needs(spec.regex, "a regex")?)?),
                25,
            )
        }
        Kind::ScriptSrc => {
            refuse(&spec.name, "name")?;
            refuse(&spec.path, "path")?;
            refuse(&spec.src, "src: its regex matches the src")?;
            (
                Source::ScriptSrc,
                Some(compile(&needs(spec.regex, "a regex")?)?),
                40,
            )
        }
        Kind::Script => {
            refuse(&spec.name, "name")?;
            refuse(&spec.path, "path")?;
            let src = compile(&needs(spec.src, "a src, which its script's src matches")?)?;
            let regex = match (spec.regex, &sha256) {
                (Some(pattern), _) => Some(compile(&pattern)?),
                (None, Some(_)) => None,
                (None, None) => return Err("this script leaf needs a regex or a sha256".into()),
            };
            (Source::Script(src), regex, 50)
        }
        Kind::NotFound => {
            refuse(&spec.name, "name")?;
            refuse(&spec.path, "path")?;
            refuse(&spec.src, "src")?;
            (
                Source::NotFound,
                Some(compile(&needs(spec.regex, "a regex")?)?),
                40,
            )
        }
        Kind::Path => {
            refuse(&spec.name, "name")?;
            refuse(&spec.src, "src")?;
            let path = needs(spec.path, "a path")?;
            let lawful = path.starts_with('/')
                && !path.starts_with("//")
                && !path.contains(|c: char| c.is_whitespace() || c == '#');
            if !lawful {
                return Err(format!(
                    "path {path:?} is not one on the host: it starts with a single /, and has no \
                     space or #"
                ));
            }
            let regex = match spec.regex {
                Some(pattern) => Some(compile(&pattern)?),
                None if version && range.is_none() && sha256.is_none() && stamp.is_none() => {
                    return Err("a version leaf needs a regex".into());
                }
                None => None,
            };
            (Source::Path(path), regex, 50)
        }
    };
    let confidence = match spec.confidence {
        Some(_) if version => return Err("a version leaf has no confidence".into()),
        Some(c) if !(1..=100).contains(&c) => {
            return Err(format!("confidence {c} is not between 1 and 100"));
        }
        Some(c) => c,
        None => confidence,
    };
    if let Some(regex) = regex
        .as_ref()
        .filter(|r| version && range.is_none() && r.captures_len() < 2)
    {
        return Err(format!("version pattern {regex} captures nothing"));
    }
    Ok(Leaf {
        source,
        regex,
        sha256,
        range,
        confidence,
        stamp,
    })
}

/// The 32 bytes 64 hex digits write, in either case.
fn sha256_of(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 || !hex.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file that does not load is left out with the reason, and the rest load. At run
    /// time the reason is printed; in the tests it fails the build.
    #[test]
    fn a_file_that_does_not_load_is_left_out_with_the_reason() {
        let good = "id: good\ninfo: { name: Good, category: CMS }\n\
                    detect: { any: [ { html: { regex: 'good' } } ] }\n";
        let x = |rest: &str| format!("info: {{ name: X, category: CMS }}\n{rest}");
        let files: Vec<(String, String)> = vec![
            ("good.yaml".into(), good.into()),
            (
                "extra-key.yaml".into(),
                format!("id: extra-key\n{}", x("tags: []\n")),
            ),
            (
                "unknown-leaf.yaml".into(),
                format!(
                    "id: unknown-leaf\n{}",
                    x("detect: { any: [ { title: { regex: 'x' } } ] }\n")
                ),
            ),
            (
                "unknown-group.yaml".into(),
                format!(
                    "id: unknown-group\n{}",
                    x("detect: { either: [ { html: { regex: 'x' } } ] }\n")
                ),
            ),
            (
                "bad-pattern.yaml".into(),
                format!(
                    "id: bad-pattern\n{}",
                    x("detect: { any: [ { html: { regex: '(' } } ] }\n")
                ),
            ),
            (
                "not-its-name.yaml".into(),
                format!("id: something-else\n{}", x("")),
            ),
            ("Upper.yaml".into(), format!("id: Upper\n{}", x(""))),
            ("good.yaml".into(), good.into()),
            (
                "no-group.yaml".into(),
                format!(
                    "id: no-group\n{}",
                    x("version: [ { html: { regex: 'x [0-9.]+' } } ]\n")
                ),
            ),
            (
                "cookie-version.yaml".into(),
                format!(
                    "id: cookie-version\n{}",
                    x("version: [ { cookie: { name: '(x)' } } ]\n")
                ),
            ),
            (
                "version-confidence.yaml".into(),
                format!(
                    "id: version-confidence\n{}",
                    x("version: [ { html: { regex: 'x ([0-9.]+)', confidence: 10 } } ]\n")
                ),
            ),
            (
                "zero.yaml".into(),
                format!(
                    "id: zero\n{}",
                    x("detect: { any: [ { html: { regex: 'x', confidence: 0 } } ] }\n")
                ),
            ),
            (
                "only-none.yaml".into(),
                format!(
                    "id: only-none\n{}",
                    x("detect: { none: [ { html: { regex: 'x' } } ] }\n")
                ),
            ),
            (
                "empty-all.yaml".into(),
                format!("id: empty-all\n{}", x("detect: { all: [] }\n")),
            ),
            (
                "off-host.yaml".into(),
                format!(
                    "id: off-host\n{}",
                    x("detect: { path: { path: '//elsewhere.test/x' } }\n")
                ),
            ),
            (
                "path-name.yaml".into(),
                format!(
                    "id: path-name\n{}",
                    x("detect: { path: { path: /x, name: y } }\n")
                ),
            ),
            (
                "script-without-src.yaml".into(),
                format!(
                    "id: script-without-src\n{}",
                    x("detect: { script: { regex: 'x' } }\n")
                ),
            ),
            (
                "script-src-with-src.yaml".into(),
                format!(
                    "id: script-src-with-src\n{}",
                    x("detect: { script_src: { regex: 'x', src: 'y' } }\n")
                ),
            ),
            (
                "header-with-src.yaml".into(),
                format!(
                    "id: header-with-src\n{}",
                    x("detect: { header: { name: server, regex: 'x', src: 'y' } }\n")
                ),
            ),
            (
                "not-found-path.yaml".into(),
                format!(
                    "id: not-found-path\n{}",
                    x("detect: { not_found: { regex: 'x', path: /y } }\n")
                ),
            ),
            (
                "short-sha.yaml".into(),
                format!(
                    "id: short-sha\n{}",
                    x("detect: { path: { path: /x, sha256: 'abc' } }\n")
                ),
            ),
            (
                "sha-and-regex.yaml".into(),
                format!(
                    "id: sha-and-regex\n{}",
                    x(&format!(
                        "detect: {{ path: {{ path: /x, regex: 'y', sha256: '{}' }} }}\n",
                        "0".repeat(64)
                    ))
                ),
            ),
            (
                "html-sha.yaml".into(),
                format!(
                    "id: html-sha\n{}",
                    x(&format!(
                        "detect: {{ html: {{ regex: 'y', sha256: '{}' }} }}\n",
                        "0".repeat(64)
                    ))
                ),
            ),
            (
                "version-sha.yaml".into(),
                format!(
                    "id: version-sha\n{}",
                    x(&format!(
                        "version: [ {{ path: {{ path: /x, sha256: '{}' }} }} ]\n",
                        "0".repeat(64)
                    ))
                ),
            ),
            (
                "detect-since.yaml".into(),
                format!(
                    "id: detect-since\n{}",
                    x("detect: { html: { regex: 'x', since: '1.0' } }\n")
                ),
            ),
            (
                "bad-since.yaml".into(),
                format!(
                    "id: bad-since\n{}",
                    x("version: [ { html: { regex: 'x', since: '1.0-beta' } } ]\n")
                ),
            ),
            (
                "backwards-range.yaml".into(),
                format!(
                    "id: backwards-range\n{}",
                    x("version: [ { html: { regex: 'x', since: '2.0', until: '1.9' } } ]\n")
                ),
            ),
            (
                "path-version.yaml".into(),
                format!(
                    "id: path-version\n{}",
                    x("version: [ { path: { path: /x } } ]\n")
                ),
            ),
            (
                "implies-missing.yaml".into(),
                format!("id: implies-missing\n{}", x("implies: [nowhere]\n")),
            ),
            (
                "implies-left-out.yaml".into(),
                format!(
                    "id: implies-left-out\n{}",
                    x("implies: [implies-missing]\n")
                ),
            ),
            (
                "refines-missing.yaml".into(),
                format!(
                    "id: refines-missing\n{}",
                    x("refines: nowhere\ndetect: { html: { regex: 'x' } }\n")
                ),
            ),
            (
                "banner-nameless.yaml".into(),
                format!(
                    "id: banner-nameless\n{}",
                    x("detect: { banner: { regex: 'x' } }\n")
                ),
            ),
            (
                "rendered-name.yaml".into(),
                format!(
                    "id: rendered-name\n{}",
                    x("detect: { rendered: { regex: 'x', name: y } }\n")
                ),
            ),
            (
                "tls-part.yaml".into(),
                format!(
                    "id: tls-part\n{}",
                    x("detect: { tls: { name: serial, regex: 'x' } }\n")
                ),
            ),
            (
                "distro-range.yaml".into(),
                format!(
                    "id: distro-range\n{}",
                    x("detect: { html: { regex: 'x' } }\n\
                       distro: [ { html: { regex: 'x', since: '1.0' } } ]\n")
                ),
            ),
            (
                "stamp-on-html.yaml".into(),
                format!(
                    "id: stamp-on-html\n{}",
                    x("detect: { html: { regex: 'x' } }\n\
                       version: [ { html: { regex: '(x)', stamp: netscaler } } ]\n")
                ),
            ),
            (
                "stamp-with-regex.yaml".into(),
                format!(
                    "id: stamp-with-regex\n{}",
                    x("detect: { html: { regex: 'x' } }\n\
                       version: [ { path: { path: /x.gz, regex: '(x)', stamp: netscaler } } ]\n")
                ),
            ),
            (
                "stamp-unknown.yaml".into(),
                format!(
                    "id: stamp-unknown\n{}",
                    x("detect: { html: { regex: 'x' } }\n\
                       version: [ { path: { path: /x.gz, stamp: nowhere } } ]\n")
                ),
            ),
            (
                "stamp-detects.yaml".into(),
                format!(
                    "id: stamp-detects\n{}",
                    x("detect: { path: { path: /x.gz, stamp: netscaler } }\n")
                ),
            ),
            (
                "loop-a.yaml".into(),
                format!(
                    "id: loop-a\n{}",
                    x("refines: loop-b\ndetect: { html: { regex: 'a' } }\n")
                ),
            ),
            (
                "loop-b.yaml".into(),
                format!(
                    "id: loop-b\n{}",
                    x("refines: loop-a\ndetect: { html: { regex: 'b' } }\n")
                ),
            ),
        ];
        let files: Vec<(&str, &str)> = files
            .iter()
            .map(|(f, t)| (f.as_str(), t.as_str()))
            .collect();
        let (signatures, skipped) = load(&files);
        let ids: Vec<&str> = signatures.list.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, ["good"]);
        let why = |file: &str| {
            skipped
                .iter()
                .filter(|s| s.starts_with(&format!("{file}: ")))
                .cloned()
                .collect::<Vec<_>>()
        };
        let expected = [
            ("extra-key.yaml", "unknown field `tags`"),
            (
                "stamp-on-html.yaml",
                "only a version leaf on a path reads a stamp",
            ),
            (
                "stamp-with-regex.yaml",
                "reads its version from its table, with no regex",
            ),
            ("stamp-unknown.yaml", "there is no stamp table \"nowhere\""),
            (
                "stamp-detects.yaml",
                "only a version leaf on a path reads a stamp",
            ),
            ("unknown-leaf.yaml", "unknown leaf `title`"),
            ("unknown-group.yaml", "unknown leaf `either`"),
            ("bad-pattern.yaml", "does not compile"),
            ("not-its-name.yaml", "its id is something-else"),
            ("Upper.yaml", "lower case letters, digits and hyphens"),
            ("good.yaml", "another file has the id good"),
            ("no-group.yaml", "captures nothing"),
            ("cookie-version.yaml", "a cookie leaf reads no version"),
            (
                "version-confidence.yaml",
                "a version leaf has no confidence",
            ),
            ("zero.yaml", "confidence 0 is not between 1 and 100"),
            ("only-none.yaml", "could hold with no evidence found"),
            ("empty-all.yaml", "`all` lists nothing"),
            ("off-host.yaml", "is not one on the host"),
            ("path-name.yaml", "this path leaf has no name"),
            ("script-without-src.yaml", "this script leaf needs a src"),
            (
                "script-src-with-src.yaml",
                "this script_src leaf has no src",
            ),
            ("header-with-src.yaml", "this header leaf has no src"),
            ("not-found-path.yaml", "this not_found leaf has no path"),
            ("detect-since.yaml", "only a version leaf does"),
            ("bad-since.yaml", "is not a version"),
            ("backwards-range.yaml", "since 2.0 is not before until 1.9"),
            ("short-sha.yaml", "is not 64 hex digits"),
            ("sha-and-regex.yaml", "a regex or a sha256, not both"),
            ("html-sha.yaml", "this html leaf has no sha256"),
            (
                "version-sha.yaml",
                "reads its version with a regex, not a sha256",
            ),
            ("path-version.yaml", "a version leaf needs a regex"),
            ("implies-missing.yaml", "it implies nowhere"),
            ("implies-left-out.yaml", "it implies implies-missing"),
            ("refines-missing.yaml", "it refines nowhere"),
            ("banner-nameless.yaml", "this banner leaf needs a name"),
            (
                "tls-part.yaml",
                "reads the certificate's subject or issuer, not serial",
            ),
            ("rendered-name.yaml", "this rendered leaf has no name"),
            ("distro-range.yaml", "a distro leaf reads a tag"),
            ("loop-a.yaml", "comes back round to it"),
            ("loop-b.yaml", "comes back round to it"),
        ];
        for (file, says) in expected {
            let reasons = why(file);
            assert!(
                reasons.len() == 1 && reasons[0].contains(says),
                "{file}: {reasons:?}, all: {skipped:#?}"
            );
        }
        assert_eq!(skipped.len(), expected.len(), "{skipped:#?}");
    }
}

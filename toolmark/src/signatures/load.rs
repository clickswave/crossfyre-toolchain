//! Reading signature files: what a file may hold, and why one is left out.

use super::{Leaf, MetaFinder, Node, Signature, Signatures, Source};
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
struct LeafSpec {
    name: Option<String>,
    regex: Option<String>,
    path: Option<String>,
    src: Option<String>,
    confidence: Option<u32>,
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
    if spec.refines.is_some() && detect.is_none() {
        return Err("it refines another, and has nothing to detect".into());
    }
    let version = spec
        .version
        .into_iter()
        .map(|v| {
            let (kind, value) = one_key(v)?;
            leaf(&kind, value, true)
        })
        .collect::<Result<_, String>>()?;
    Ok(Signature {
        id: spec.id,
        name: spec.info.name,
        category: spec.info.category,
        cpe: spec
            .info
            .metadata
            .map(|m| (m.vendor, m.product, m.target_sw)),
        implies: spec.implies,
        refines: spec.refines,
        detect,
        version,
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
    }
    let known = match kind {
        "header" => Kind::Header,
        "cookie" => Kind::Cookie,
        "meta" => Kind::Meta,
        "html" => Kind::Html,
        "script_src" => Kind::ScriptSrc,
        "path" => Kind::Path,
        "script" => Kind::Script,
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
    let (source, regex, confidence) = match known {
        Kind::Header => {
            refuse(&spec.path, "path")?;
            refuse(&spec.src, "src")?;
            let name = needs(spec.name, "a name")?.to_ascii_lowercase();
            let regex = compile(&needs(spec.regex, "a regex")?)?;
            (Source::Header(name), Some(regex), 50)
        }
        Kind::Cookie => {
            if version {
                return Err("a cookie leaf reads no version".into());
            }
            refuse(&spec.regex, "regex: it matches the cookie's name")?;
            refuse(&spec.path, "path")?;
            refuse(&spec.src, "src")?;
            (
                Source::Cookie,
                Some(compile(&needs(spec.name, "a name")?)?),
                45,
            )
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
            let regex = compile(&needs(spec.regex, "a regex")?)?;
            (Source::Script(src), Some(regex), 50)
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
                None if version => return Err("a version leaf needs a regex".into()),
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
    if let Some(regex) = regex.as_ref().filter(|r| version && r.captures_len() < 2) {
        return Err(format!("version pattern {regex} captures nothing"));
    }
    Ok(Leaf {
        source,
        regex,
        confidence,
    })
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
                format!("id: extra-key\n{}", x("distro: []\n")),
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
            (
                "refines-blind.yaml".into(),
                format!("id: refines-blind\n{}", x("refines: good\n")),
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
            ("extra-key.yaml", "unknown field `distro`"),
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
            ("path-version.yaml", "a version leaf needs a regex"),
            ("implies-missing.yaml", "it implies nowhere"),
            ("implies-left-out.yaml", "it implies implies-missing"),
            ("refines-missing.yaml", "it refines nowhere"),
            ("loop-a.yaml", "comes back round to it"),
            ("loop-b.yaml", "comes back round to it"),
            ("refines-blind.yaml", "has nothing to detect"),
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

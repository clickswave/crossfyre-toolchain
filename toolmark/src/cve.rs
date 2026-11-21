//! CVE leads: the CVEs that may affect a technology toolmark found, at the version it
//! read, from the CVE dataset `crossfyre update` puts in toolmark's data folder or, with
//! none there that reads, the known-exploited snapshot compiled in; and the mappings that
//! say what other names the CVE data gives a product, and how it numbers a product whose
//! CVEs are filed under other numbering than toolmark reads. A lead is a version match,
//! never a confirmed finding: a version can be read wrong, and a build may carry a fix
//! its version does not show.

use cfx_cve::{Cpe, Dataset, Version};
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// The known-exploited CVEs of the dataset, cut at the last release (toolmark/data).
const SNAPSHOT: &[u8] = include_bytes!("../data/cve-known-exploited.json.gz");

/// What a lead from the snapshot says of where it came from.
pub const SNAPSHOT_LABEL: &str = "built-in known-exploited snapshot";

/// The aliases `text` gives, as aliases.yaml writes them, or what is wrong with it.
fn read_aliases(text: &str) -> Result<HashMap<Cpe, Vec<Cpe>>, String> {
    let read: std::collections::BTreeMap<String, Vec<String>> =
        serde_yaml::from_str(text).map_err(|e| e.to_string())?;
    read.into_iter()
        .map(|(name, also)| {
            Ok((
                named(&name)?,
                also.iter().map(|a| named(a)).collect::<Result<_, _>>()?,
            ))
        })
        .collect()
}

/// A name in a mapping, part:vendor:product.
fn named(text: &str) -> Result<Cpe, String> {
    Cpe::parse(text).ok_or_else(|| format!("{text:?} is not part:vendor:product"))
}

/// One way a version toolmark reads maps to the one the CVE data files it under: an
/// exact version, or a range from one up to and not including another.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Filed {
    eq: Option<String>,
    from: Option<String>,
    below: Option<String>,
    #[serde(rename = "as")]
    filed: String,
}

impl Filed {
    fn holds(&self, v: &Version) -> bool {
        let at = |bound: &Option<String>| bound.as_deref().and_then(Version::parse);
        at(&self.eq).is_none_or(|b| *v == b)
            && at(&self.from).is_none_or(|b| *v >= b)
            && at(&self.below).is_none_or(|b| *v < b)
    }
}

/// The version maps `text` gives, as versions.yaml writes them, or what is wrong with it:
/// a name that is not part:vendor:product, or a bound that is no version.
fn read_versions(text: &str) -> Result<HashMap<Cpe, Vec<Filed>>, String> {
    let read: std::collections::BTreeMap<String, Vec<Filed>> =
        serde_yaml::from_str(text).map_err(|e| e.to_string())?;
    read.into_iter()
        .map(|(name, map)| {
            for f in &map {
                for bound in [&f.eq, &f.from, &f.below].into_iter().flatten() {
                    Version::parse(bound)
                        .ok_or_else(|| format!("{name}: {bound:?} is no version"))?;
                }
                if f.eq.is_none() && f.from.is_none() && f.below.is_none() {
                    return Err(format!("{name}: an entry for {:?} has no version", f.filed));
                }
            }
            Ok((named(&name)?, map))
        })
        .collect()
}

/// What the CVE data calls the products toolmark names, and how it numbers them: the
/// aliases and the version maps.
pub(crate) struct Mappings {
    aliases: HashMap<Cpe, Vec<Cpe>>,
    versions: HashMap<Cpe, Vec<Filed>>,
}

impl Mappings {
    /// The mappings in aliases.yaml's and versions.yaml's text, or what is wrong with
    /// either.
    pub(crate) fn read(aliases: &str, versions: &str) -> Result<Self, String> {
        Ok(Self {
            aliases: read_aliases(aliases).map_err(|e| format!("aliases.yaml: {e}"))?,
            versions: read_versions(versions).map_err(|e| format!("versions.yaml: {e}"))?,
        })
    }

    /// `version` of `cpe` as the CVE data numbers it: itself, or for a product whose CVEs
    /// are filed under other numbering, what its map gives, and none when the map has
    /// nothing for it.
    pub(crate) fn as_filed(&self, cpe: &Cpe, version: &str) -> Option<String> {
        let Some(map) = self.versions.get(cpe) else {
            return Some(version.to_string());
        };
        let v = Version::parse(version)?;
        map.iter().find(|f| f.holds(&v)).map(|f| f.filed.clone())
    }

    /// `cpe` and its other names.
    pub(crate) fn with_aliases(&self, cpe: &Cpe) -> Vec<Cpe> {
        let mut names = vec![cpe.clone()];
        names.extend(self.aliases.get(cpe).into_iter().flatten().cloned());
        names
    }
}

/// The dataset at `path` and what its leads say of it, or none when there is no file or
/// it does not read, which is said.
pub(crate) fn read(path: &Path, names: &HashSet<Cpe>) -> Option<(Dataset, String)> {
    let bytes = std::fs::read(path).ok()?;
    match Dataset::from_bytes_for(&bytes, names) {
        Ok(d) => {
            let label = label(&d);
            Some((d, label))
        }
        Err(e) => {
            eprintln!(
                "[toolmark] the CVE dataset in {} is not used: {e}",
                path.display()
            );
            None
        }
    }
}

/// What a lead from `d` says of where it came from.
fn label(d: &Dataset) -> String {
    let made = d.made().get(..10).unwrap_or(d.made());
    format!("CVE dataset {} of {made}", d.sequence())
}

/// The snapshot compiled in, with only the products `names` name, and what its leads say
/// of it.
pub(crate) fn snapshot(names: &HashSet<Cpe>) -> (Dataset, String) {
    let d = Dataset::from_bytes_for(SNAPSHOT, names)
        .expect("the snapshot compiled into toolmark reads, as its test shows");
    (d, SNAPSHOT_LABEL.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mapping that does not read says what is wrong with it rather than being read
    /// in part.
    #[test]
    fn a_mapping_that_does_not_read_says_why() {
        let aliases = read_aliases(r#""a:acme:widget": ["a:acme:gadget"]"#).unwrap();
        assert_eq!(
            aliases[&Cpe::new("a", "acme", "widget")],
            [Cpe::new("a", "acme", "gadget")]
        );
        assert_eq!(
            read_aliases(r#""a:acme:widget": ["acme:gadget"]"#)
                .err()
                .as_deref(),
            Some(r#""acme:gadget" is not part:vendor:product"#)
        );
        assert!(read_aliases("[").is_err());

        let versions =
            read_versions(r#""a:acme:widget": [{from: "1.0", below: "2.0", as: "one"}]"#).unwrap();
        assert_eq!(versions[&Cpe::new("a", "acme", "widget")].len(), 1);
        assert_eq!(
            read_versions(r#""a:acme:widget": [{eq: "none", as: "one"}]"#)
                .err()
                .as_deref(),
            Some(r#"a:acme:widget: "none" is no version"#)
        );
        assert_eq!(
            read_versions(r#""a:acme:widget": [{as: "one"}]"#)
                .err()
                .as_deref(),
            Some(r#"a:acme:widget: an entry for "one" has no version"#)
        );
        assert!(read_versions(r#""acme": [{eq: "1", as: "one"}]"#).is_err());
        assert!(read_versions(r#""a:acme:widget": [{eq: "1", as: "one", to: "2"}]"#).is_err());
    }
}

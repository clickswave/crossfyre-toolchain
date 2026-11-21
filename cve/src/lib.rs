//! A CVE dataset, and which of its CVEs affect a product at a version.
//!
//! The dataset is one gzipped JSON file, made once a day:
//!
//! ```json
//! {
//!   "format": 1,
//!   "sequence": 42,
//!   "made": "2026-11-20T03:00:00Z",
//!   "products": [
//!     {"part": "a", "vendor": "apache", "product": "http_server", "affected": [
//!       {"cve": "CVE-2021-41773", "ranges": [{"eq": "2.4.49"}]}
//!     ]},
//!     {"part": "npm", "vendor": "", "product": "jquery", "affected": [
//!       {"cve": "CVE-2020-11022", "ranges": [{"ge": "1.2.0", "lt": "3.5.0"}]}
//!     ]}
//!   ],
//!   "cves": {
//!     "CVE-2021-41773": {"severity": "high", "score": 7.5, "kev": true, "epss": 0.944},
//!     "CVE-2020-11022": {"severity": "medium", "score": 6.1, "epss": 0.992}
//!   }
//! }
//! ```
//!
//! `products` holds, for each CPE part, vendor and product, the CVEs that affect it and at
//! which versions. A package from an ecosystem's registry is named with the ecosystem as
//! its part and no vendor. A range has any of `eq`, `ge`, `gt`, `le` and `lt`, and a
//! version is in it when it meets each bound it has. A CVE affects a version in any of its
//! ranges. `cves` holds what is known of each CVE: its CVSS severity and score, whether
//! it is on CISA's known-exploited list, and its EPSS score.
//!
//! The whole dataset is large: millions of ranges. A caller that asks about a known set
//! of products loads only those ([`Dataset::from_bytes_for`]), and as the products come
//! before the CVEs, keeps only the CVEs they name as it reads.
//!
//! A version matched here makes a lead, never a confirmed finding: a version can be read
//! wrong, and a distribution's build may carry a fix its version does not show.

mod version;

pub use version::Version;

use serde::Deserialize;
use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

/// The dataset format this crate reads.
pub const FORMAT: u32 = 1;

/// A product as a CPE names it: its part (`a` for an application, `o` for an operating
/// system), vendor and product.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Cpe {
    pub part: String,
    pub vendor: String,
    pub product: String,
}

impl Cpe {
    pub fn new(part: &str, vendor: &str, product: &str) -> Self {
        Self {
            part: part.to_ascii_lowercase(),
            vendor: vendor.to_ascii_lowercase(),
            product: product.to_ascii_lowercase(),
        }
    }

    /// The product a CPE 2.3 name names, as in `cpe:2.3:a:apache:http_server:2.4.49:...`,
    /// with its escapes undone, or none when it is not one.
    pub fn from_cpe23(name: &str) -> Option<Self> {
        let rest = name.strip_prefix("cpe:2.3:")?;
        let mut fields = Vec::new();
        let mut field = String::new();
        let mut chars = rest.chars();
        while let Some(c) = chars.next() {
            match c {
                '\\' => field.extend(chars.next()),
                ':' => fields.push(std::mem::take(&mut field)),
                c => field.push(c),
            }
            if fields.len() == 3 {
                break;
            }
        }
        if fields.len() < 3 {
            fields.push(field);
        }
        let [part, vendor, product] = fields.get(..3)? else {
            return None;
        };
        let named = |f: &String| !f.is_empty() && f != "*" && f != "-";
        (named(part) && named(vendor) && named(product)).then(|| Self::new(part, vendor, product))
    }
}

impl fmt::Display for Cpe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.part, self.vendor, self.product)
    }
}

/// What the dataset knows of one CVE.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct Known {
    /// CVSS severity: critical, high, medium, low or none.
    #[serde(default)]
    pub severity: Option<String>,
    /// CVSS base score.
    #[serde(default)]
    pub score: Option<f32>,
    /// On CISA's known-exploited list.
    #[serde(default)]
    pub kev: bool,
    /// EPSS: the chance it is exploited in the next 30 days.
    #[serde(default)]
    pub epss: Option<f32>,
}

/// A CVE that may affect what was fingerprinted: a lead to check, never a confirmed
/// finding.
#[derive(Debug, Clone, PartialEq)]
pub struct Lead {
    pub cve: String,
    pub known: Known,
    /// The products asked about that it affects at the version.
    pub affects: Vec<Cpe>,
    /// It affects some of the products asked about and not others, so whether it applies
    /// depends on which of them this is.
    pub possible: bool,
    /// A distribution built the version, and its build may carry a fix for it.
    pub backport: bool,
}

/// Why a dataset could not be read.
#[derive(Debug)]
pub struct Error(String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

/// A loaded dataset.
#[derive(Debug)]
pub struct Dataset {
    sequence: u64,
    made: String,
    cves: HashMap<String, Known>,
    products: HashMap<Cpe, Vec<Affected>>,
}

/// One CVE's ranges for one product.
#[derive(Debug)]
struct Affected {
    cve: String,
    ranges: Vec<Range>,
}

/// Versions between bounds; a version is in it when it meets every bound it has.
#[derive(Debug)]
struct Range {
    eq: Option<Version>,
    ge: Option<Version>,
    gt: Option<Version>,
    le: Option<Version>,
    lt: Option<Version>,
}

impl Range {
    fn holds(&self, v: &Version) -> bool {
        self.eq.as_ref().is_none_or(|b| v == b)
            && self.ge.as_ref().is_none_or(|b| v >= b)
            && self.gt.as_ref().is_none_or(|b| v > b)
            && self.le.as_ref().is_none_or(|b| v <= b)
            && self.lt.as_ref().is_none_or(|b| v < b)
    }
}

#[derive(Deserialize)]
struct AffectedFile {
    cve: String,
    ranges: Vec<BTreeMap<String, String>>,
}

/// Which products a load keeps.
type Keep<'a> = &'a dyn Fn(&Cpe) -> bool;

/// The file as read: the products a load keeps, and the CVEs, only those the kept
/// products name when the products come first.
#[derive(Default)]
struct Read {
    format: Option<u32>,
    sequence: Option<u64>,
    made: Option<String>,
    cves: HashMap<String, Known>,
    products: Vec<(Cpe, Vec<AffectedFile>)>,
}

impl Dataset {
    /// The dataset in `bytes`, gzipped as it is published or as plain JSON.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Self::load(bytes, &|_| true)
    }

    /// The dataset in `bytes`, with only the products `names` name: all a caller that
    /// asks about a known set of products needs, in a small part of the memory.
    pub fn from_bytes_for(bytes: &[u8], names: &HashSet<Cpe>) -> Result<Self, Error> {
        Self::load(bytes, &|cpe| names.contains(cpe))
    }

    fn load(bytes: &[u8], keep: Keep) -> Result<Self, Error> {
        let unreadable =
            |e: serde_json::Error| Error(format!("the dataset is not one this reads: {e}"));
        let mut file = if bytes.starts_with(&[0x1f, 0x8b]) {
            let gz = std::io::BufReader::new(flate2::read::GzDecoder::new(bytes));
            let mut json = serde_json::Deserializer::from_reader(gz);
            let file = FileSeed(keep).deserialize(&mut json).map_err(unreadable)?;
            json.end().map_err(unreadable)?;
            file
        } else {
            let mut json = serde_json::Deserializer::from_slice(bytes);
            let file = FileSeed(keep).deserialize(&mut json).map_err(unreadable)?;
            json.end().map_err(unreadable)?;
            file
        };
        let (Some(format), Some(sequence), Some(made)) =
            (file.format, file.sequence, file.made.take())
        else {
            return Err(Error(
                "the dataset has no format, sequence or time it was made".to_string(),
            ));
        };
        if format != FORMAT {
            return Err(Error(format!(
                "the dataset is in format {format}, and this reads format {FORMAT}"
            )));
        }
        let named: HashSet<&str> = file
            .products
            .iter()
            .flat_map(|(_, affected)| affected.iter().map(|a| a.cve.as_str()))
            .collect();
        file.cves.retain(|id, _| named.contains(id.as_str()));
        let mut products: HashMap<Cpe, Vec<Affected>> = HashMap::new();
        for (cpe, affected) in file.products {
            for a in affected {
                if !file.cves.contains_key(&a.cve) {
                    return Err(Error(format!(
                        "{cpe} names {}, which it does not hold",
                        a.cve
                    )));
                }
                let ranges = a
                    .ranges
                    .iter()
                    .map(|r| range(r).map_err(|why| Error(format!("{} on {cpe}: {why}", a.cve))))
                    .collect::<Result<Vec<_>, _>>()?;
                products
                    .entry(cpe.clone())
                    .or_default()
                    .push(Affected { cve: a.cve, ranges });
            }
        }
        Ok(Self {
            sequence,
            made,
            cves: file.cves,
            products,
        })
    }

    /// What the dataset knows of `cve`, when a product it holds names it.
    pub fn known(&self, cve: &str) -> Option<&Known> {
        self.cves.get(cve)
    }

    /// Which of the datasets made it is: each is numbered one more than the last.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// When it was made, in RFC 3339.
    pub fn made(&self) -> &str {
        &self.made
    }

    /// The CVEs that affect `version` of what `names` name. One product is one name. A
    /// product the CPE dictionary splits in several, or a base whose candidates are each
    /// a product, is several: the leads are those of any of them, and one that affects
    /// only some of them is possible. With `distro`, the tag of the distribution that
    /// built it, or a distribution's suffix on the version, each lead says the build may
    /// carry a backported fix. Known-exploited first, then by score.
    pub fn leads(&self, names: &[Cpe], version: &str, distro: Option<&str>) -> Vec<Lead> {
        let Some(version) = Version::parse(version) else {
            return Vec::new();
        };
        let mut names = names.to_vec();
        names.sort();
        names.dedup();
        let backport = distro.is_some_and(|d| !d.trim().is_empty()) || version.distro();
        let mut affects: BTreeMap<&str, Vec<Cpe>> = BTreeMap::new();
        for name in &names {
            for a in self.products.get(name).into_iter().flatten() {
                if a.ranges.iter().any(|r| r.holds(&version)) {
                    affects.entry(&a.cve).or_default().push(name.clone());
                }
            }
        }
        let mut leads: Vec<Lead> = affects
            .into_iter()
            .map(|(cve, affects)| Lead {
                cve: cve.to_string(),
                known: self.cves.get(cve).cloned().unwrap_or_default(),
                possible: affects.len() < names.len(),
                affects,
                backport,
            })
            .collect();
        leads.sort_by(|a, b| {
            b.known
                .kev
                .cmp(&a.known.kev)
                .then(
                    b.known
                        .score
                        .unwrap_or(-1.0)
                        .total_cmp(&a.known.score.unwrap_or(-1.0)),
                )
                .then_with(|| a.cve.cmp(&b.cve))
        });
        leads
    }
}

/// A range as the dataset writes it: each of its bounds a version, and at least one.
fn range(bounds: &BTreeMap<String, String>) -> Result<Range, String> {
    let mut range = Range {
        eq: None,
        ge: None,
        gt: None,
        le: None,
        lt: None,
    };
    for (bound, text) in bounds {
        let version = Version::parse(text).ok_or_else(|| format!("{text:?} is no version"))?;
        let slot = match bound.as_str() {
            "eq" => &mut range.eq,
            "ge" => &mut range.ge,
            "gt" => &mut range.gt,
            "le" => &mut range.le,
            "lt" => &mut range.lt,
            other => return Err(format!("{other:?} is no bound")),
        };
        *slot = Some(version);
    }
    if bounds.is_empty() {
        // A range with no bound would make every version of the product a lead.
        return Err("a range with no bound".to_string());
    }
    Ok(range)
}

/// Reads the file, keeping what a load wants of it.
struct FileSeed<'a>(Keep<'a>);

impl<'de> DeserializeSeed<'de> for FileSeed<'_> {
    type Value = Read;
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Read, D::Error> {
        d.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for FileSeed<'_> {
    type Value = Read;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a CVE dataset")
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Read, M::Error> {
        let mut out = Read::default();
        let mut named: Option<HashSet<String>> = None;
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "format" => out.format = Some(map.next_value()?),
                "sequence" => out.sequence = Some(map.next_value()?),
                "made" => out.made = Some(map.next_value()?),
                "products" => {
                    out.products = map.next_value_seed(ProductsSeed(self.0))?;
                    named = Some(
                        out.products
                            .iter()
                            .flat_map(|(_, affected)| affected.iter().map(|a| a.cve.clone()))
                            .collect(),
                    );
                }
                "cves" => out.cves = map.next_value_seed(CvesSeed(named.as_ref()))?,
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(out)
    }
}

/// Reads the products, keeping those a load wants.
struct ProductsSeed<'a>(Keep<'a>);

impl<'de> DeserializeSeed<'de> for ProductsSeed<'_> {
    type Value = Vec<(Cpe, Vec<AffectedFile>)>;
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for ProductsSeed<'_> {
    type Value = Vec<(Cpe, Vec<AffectedFile>)>;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a list of products")
    }
    fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
        let mut out = Vec::new();
        while let Some(product) = seq.next_element_seed(ProductSeed(self.0))? {
            out.extend(product);
        }
        Ok(out)
    }
}

/// Reads one product, skipping what it affects unread when a load does not want it.
struct ProductSeed<'a>(Keep<'a>);

impl<'de> DeserializeSeed<'de> for ProductSeed<'_> {
    type Value = Option<(Cpe, Vec<AffectedFile>)>;
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for ProductSeed<'_> {
    type Value = Option<(Cpe, Vec<AffectedFile>)>;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a product")
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        let (mut part, mut vendor, mut product) = (None::<String>, None::<String>, None::<String>);
        let mut affected = None;
        let mut skipped = false;
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "part" => part = Some(map.next_value()?),
                "vendor" => vendor = Some(map.next_value()?),
                "product" => product = Some(map.next_value()?),
                "affected" => {
                    // Its name comes first as the dataset is written; when it does not,
                    // what it affects is read, and dropped once the name says so.
                    let wanted = match (&part, &vendor, &product) {
                        (Some(p), Some(v), Some(name)) => (self.0)(&Cpe::new(p, v, name)),
                        _ => true,
                    };
                    if wanted {
                        affected = Some(map.next_value::<Vec<AffectedFile>>()?);
                    } else {
                        map.next_value::<IgnoredAny>()?;
                        skipped = true;
                    }
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        let (Some(part), Some(vendor), Some(product)) = (part, vendor, product) else {
            return Err(de::Error::custom(
                "a product without its part, vendor or product",
            ));
        };
        let cpe = Cpe::new(&part, &vendor, &product);
        if skipped || !(self.0)(&cpe) {
            return Ok(None);
        }
        let affected = affected.ok_or_else(|| de::Error::missing_field("affected"))?;
        Ok(Some((cpe, affected)))
    }
}

/// Reads the CVEs: those the kept products name when the products came first, else all.
struct CvesSeed<'a>(Option<&'a HashSet<String>>);

impl<'de> DeserializeSeed<'de> for CvesSeed<'_> {
    type Value = HashMap<String, Known>;
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for CvesSeed<'_> {
    type Value = HashMap<String, Known>;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("the CVEs")
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        let mut out = HashMap::new();
        while let Some(id) = map.next_key::<String>()? {
            if self.0.is_none_or(|named| named.contains(&id)) {
                let known = map.next_value::<Known>()?;
                out.insert(id, known);
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// A hand-made dataset: Apache's two path-traversal CVEs and OpenSSH's regreSSHion as
    /// their advisories give them, and made-up products that share or split a CVE.
    const SMALL: &str = include_str!("../tests/small.json");

    fn small() -> Dataset {
        Dataset::from_bytes(SMALL.as_bytes()).expect("the small dataset")
    }

    fn ids(leads: &[Lead]) -> Vec<&str> {
        leads.iter().map(|l| l.cve.as_str()).collect()
    }

    fn apache() -> Vec<Cpe> {
        vec![Cpe::new("a", "apache", "http_server")]
    }

    #[test]
    fn apache_2_4_49_has_both_path_traversals_and_2_4_51_neither() {
        let d = small();
        assert_eq!(
            ids(&d.leads(&apache(), "2.4.49", None)),
            ["CVE-2021-42013", "CVE-2021-41773"]
        );
        assert_eq!(ids(&d.leads(&apache(), "2.4.50", None)), ["CVE-2021-42013"]);
        assert!(d.leads(&apache(), "2.4.51", None).is_empty());
        assert!(d.leads(&apache(), "2.4.48", None).is_empty());
    }

    #[test]
    fn a_lead_carries_what_is_known_of_its_cve() {
        let leads = small().leads(&apache(), "2.4.49", None);
        let lead = leads.iter().find(|l| l.cve == "CVE-2021-41773").unwrap();
        assert!(lead.known.kev);
        assert_eq!(lead.known.severity.as_deref(), Some("high"));
        assert_eq!(lead.affects, apache());
        assert!(!lead.possible && !lead.backport);
    }

    #[test]
    fn openssh_s_portable_releases_are_matched_in_order() {
        let d = small();
        let openssh = [Cpe::new("a", "openbsd", "openssh")];
        for (version, hit) in [
            ("4.3p2", true),
            ("4.4p1", false),
            ("8.4p1", false),
            ("8.5p1", true),
            ("8.9p1", true),
            ("9.7p1", true),
            ("9.8p1", false),
        ] {
            let leads = d.leads(&openssh, version, None);
            assert_eq!(!leads.is_empty(), hit, "{version}: {:?}", ids(&leads));
        }
    }

    #[test]
    fn a_distribution_s_build_may_carry_a_backported_fix() {
        let d = small();
        let openssh = [Cpe::new("a", "openbsd", "openssh")];
        let tagged = d.leads(&openssh, "8.9p1", Some("Ubuntu-3ubuntu0.6"));
        assert!(!tagged.is_empty() && tagged.iter().all(|l| l.backport));
        let suffixed = d.leads(&apache(), "2.4.49-1ubuntu1", None);
        assert_eq!(ids(&suffixed), ["CVE-2021-42013", "CVE-2021-41773"]);
        assert!(suffixed.iter().all(|l| l.backport));
        assert!(d.leads(&openssh, "8.9p1", None).iter().all(|l| !l.backport));
    }

    #[test]
    fn several_names_give_every_cve_of_any_and_mark_those_of_some_possible() {
        let d = small();
        // The appliance's two editions share one CVE; the other is the gateway's alone.
        let both = [
            Cpe::new("a", "example", "appliance_gateway"),
            Cpe::new("a", "example", "appliance_controller"),
        ];
        let leads = d.leads(&both, "13.1-49.12", None);
        assert_eq!(ids(&leads), ["CVE-2099-0001", "CVE-2099-0002"]);
        assert!(!leads[0].possible, "it affects both, whichever this is");
        assert_eq!(leads[0].affects.len(), 2);
        assert!(leads[1].possible, "it affects the gateway only");
        assert_eq!(leads[1].affects, [both[0].clone()]);
        assert!(d.leads(&both, "13.1-49.13", None).is_empty());
        // Asked about one edition alone, nothing is possible.
        let gateway = d.leads(&both[..1], "13.1-49.12", None);
        assert_eq!(ids(&gateway), ["CVE-2099-0001", "CVE-2099-0002"]);
        assert!(gateway.iter().all(|l| !l.possible));
    }

    #[test]
    fn a_cpe_2_3_name_gives_its_product() {
        assert_eq!(
            Cpe::from_cpe23("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"),
            Some(Cpe::new("a", "apache", "http_server"))
        );
        assert_eq!(
            Cpe::from_cpe23(r"cpe:2.3:a:nodejs:node\.js:*:*:*:*:*:*:*:*"),
            Some(Cpe::new("a", "nodejs", "node.js"))
        );
        assert_eq!(
            Cpe::from_cpe23("cpe:2.3:o:fortinet:fortios"),
            Some(Cpe::new("o", "fortinet", "fortios"))
        );
        for not in [
            "",
            "cpe:/a:apache:http_server",
            "cpe:2.3:a:apache",
            "cpe:2.3:a:*:*:1.0",
        ] {
            assert_eq!(Cpe::from_cpe23(not), None, "{not}");
        }
    }

    #[test]
    fn a_name_is_matched_whatever_its_case() {
        let d = small();
        let named = [Cpe::new("A", "Apache", "HTTP_Server")];
        assert_eq!(d.leads(&named, "2.4.50", None).len(), 1);
    }

    #[test]
    fn known_exploited_comes_first_then_the_higher_score() {
        let d = small();
        let os = [Cpe::new("o", "example", "firewall_os")];
        assert_eq!(
            ids(&d.leads(&os, "7.2.4", None)),
            ["CVE-2099-0011", "CVE-2099-0013", "CVE-2099-0012"]
        );
        // The same names as an application are another product.
        assert!(
            d.leads(&[Cpe::new("a", "example", "firewall_os")], "7.2.4", None)
                .is_empty()
        );
    }

    #[test]
    fn a_version_that_is_none_gives_no_lead() {
        assert!(small().leads(&apache(), "", None).is_empty());
        assert!(small().leads(&apache(), "unknown", None).is_empty());
    }

    #[test]
    fn the_published_file_is_read_gzipped() {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(SMALL.as_bytes()).unwrap();
        let gz = gz.finish().unwrap();
        let d = Dataset::from_bytes(&gz).unwrap();
        assert_eq!((d.sequence(), d.made()), (7, "2026-11-20T03:00:00Z"));
        assert_eq!(d.leads(&apache(), "2.4.49", None).len(), 2);
        let some = Dataset::from_bytes_for(&gz, &apache().into_iter().collect()).unwrap();
        assert_eq!(some.leads(&apache(), "2.4.49", None).len(), 2);
    }

    /// Products before CVEs, as the job writes them, and one product whose name comes
    /// after what it affects.
    const ORDERED: &str = r#"{"format": 1, "sequence": 2, "made": "x",
        "products": [
          {"part": "a", "vendor": "v", "product": "p",
           "affected": [{"cve": "CVE-1", "ranges": [{"lt": "2.0"}]}]},
          {"affected": [{"cve": "CVE-2", "ranges": [{"lt": "2.0"}]}],
           "part": "a", "vendor": "v", "product": "q"}
        ],
        "cves": {"CVE-1": {"kev": true}, "CVE-2": {}}}"#;

    #[test]
    fn a_load_for_some_products_keeps_only_those_and_their_cves() {
        let p = Cpe::new("a", "v", "p");
        let q = Cpe::new("a", "v", "q");
        let only_p = Dataset::from_bytes_for(ORDERED.as_bytes(), &[p.clone()].into()).unwrap();
        assert_eq!(ids(&only_p.leads(&[p.clone()], "1.0", None)), ["CVE-1"]);
        assert!(only_p.leads(&[q.clone()], "1.0", None).is_empty());
        assert!(only_p.known("CVE-1").is_some_and(|k| k.kev));
        assert!(only_p.known("CVE-2").is_none());
        let only_q = Dataset::from_bytes_for(ORDERED.as_bytes(), &[q.clone()].into()).unwrap();
        assert_eq!(ids(&only_q.leads(&[q], "1.0", None)), ["CVE-2"]);
        assert!(only_q.known("CVE-1").is_none());
        // CVEs before products, as in the small dataset, are kept for the products wanted.
        let apache_only =
            Dataset::from_bytes_for(SMALL.as_bytes(), &apache().into_iter().collect()).unwrap();
        assert_eq!(apache_only.leads(&apache(), "2.4.49", None).len(), 2);
        assert!(apache_only.known("CVE-2024-6387").is_none());
        assert!(apache_only.known("CVE-2021-41773").is_some());
    }

    #[test]
    fn a_dataset_that_is_wrong_is_refused_and_says_why() {
        let with = |cves: &str, ranges: &str, format: u32| {
            format!(
                r#"{{"format": {format}, "sequence": 1, "made": "x", "cves": {cves},
                "products": [{{"part": "a", "vendor": "v", "product": "p",
                "affected": [{{"cve": "CVE-1", "ranges": {ranges}}}]}}]}}"#
            )
        };
        let one = r#"{"CVE-1": {}}"#;
        for (text, why) in [
            (with(one, r#"[{"lt": "2.0"}]"#, 2), "format 2"),
            (with(one, "[{}]", 1), "no bound"),
            (with(one, r#"[{"lt": "*"}]"#, 1), "is no version"),
            (with(one, r#"[{"below": "2.0"}]"#, 1), "is no bound"),
            (with("{}", r#"[{"lt": "2.0"}]"#, 1), "does not hold"),
        ] {
            let e = Dataset::from_bytes(text.as_bytes())
                .unwrap_err()
                .to_string();
            assert!(e.contains(why), "{e}");
        }
        assert!(Dataset::from_bytes(with(one, r#"[{"lt": "2.0"}]"#, 1).as_bytes()).is_ok());
    }
}

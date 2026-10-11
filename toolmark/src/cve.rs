//! Version-based CVE matching.
//!
//! Given a detected product + version (from fingerprinting), match it against a
//! ruleset of version-ranged CVEs. This is the same embedded-starter + external-
//! file pattern plessor uses for templates, so the ruleset extends to a full feed
//! (NVD/CPE export) by dropping a JSON file at `TOOLMARK_CVE_FILE` without a rebuild.
//!
//! Version-based matching is inherently lower-confidence than active detection:
//! a distro may backport a fix without bumping the version string, and fingerprint
//! versions are sometimes imprecise. Findings are therefore emitted as
//! `confidence: "version-inferred"`, never "confirmed".

use serde::Deserialize;
use std::cmp::Ordering;

#[derive(Debug, Deserialize, Clone)]
pub struct CveRule {
    /// Product name to match against the detected technology name (case-insensitive).
    pub product: String,
    pub cve: String,
    #[serde(default)]
    pub title: String,
    #[serde(default = "d_sev")]
    pub severity: String,
    #[serde(default)]
    pub cvss: f32,
    /// Inclusive lower bound: the vuln affects versions >= this.
    #[serde(default)]
    pub version_min: Option<String>,
    /// Exclusive upper bound ("fixed in"): affects versions < this.
    #[serde(default)]
    pub version_max_excl: Option<String>,
    /// Inclusive upper bound: affects versions <= this.
    #[serde(default)]
    pub version_max_incl: Option<String>,
    #[serde(default)]
    pub reference: String,
}

fn d_sev() -> String {
    "medium".to_string()
}

/// Match a detected product+version against the ruleset (embedded + external).
pub fn match_cves(product: &str, version: &str) -> Vec<CveRule> {
    let v = parse_ver(version);
    if v.is_empty() {
        return Vec::new(); // no usable version -> no version-based match (avoids FPs)
    }
    ruleset()
        .iter()
        .filter(|r| r.product.eq_ignore_ascii_case(product))
        .filter(|r| version_in_range(&v, r))
        .cloned()
        .collect()
}

fn version_in_range(v: &[u64], r: &CveRule) -> bool {
    if let Some(min) = &r.version_min
        && cmp_ver(v, &parse_ver(min)) == Ordering::Less
    {
        return false;
    }
    if let Some(max) = &r.version_max_excl
        && cmp_ver(v, &parse_ver(max)) != Ordering::Less
    {
        return false;
    }
    if let Some(max) = &r.version_max_incl
        && cmp_ver(v, &parse_ver(max)) == Ordering::Greater
    {
        return false;
    }
    // A rule with no bounds at all would match every version; reject it so a
    // malformed rule can't blanket-flag a product.
    r.version_min.is_some() || r.version_max_excl.is_some() || r.version_max_incl.is_some()
}

/// Parse a dotted version into numeric components, stopping at the first
/// non-numeric segment ("1.21.0" -> [1,21,0], "2.4.49" -> [2,4,49]).
fn parse_ver(s: &str) -> Vec<u64> {
    let mut out = Vec::new();
    for part in s
        .trim()
        .trim_start_matches('v')
        .split(['.', '-', '+', '_', ' '])
    {
        if part.is_empty() {
            continue;
        }
        // Take the leading digit run of each segment ("49p1" -> 49).
        let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            break;
        }
        match digits.parse::<u64>() {
            Ok(n) => out.push(n),
            Err(_) => break,
        }
    }
    out
}

fn cmp_ver(a: &[u64], b: &[u64]) -> Ordering {
    for i in 0..a.len().max(b.len()) {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        match x.cmp(&y) {
            Ordering::Equal => continue,
            o => return o,
        }
    }
    Ordering::Equal
}

/// Embedded + external ruleset. External rules (a JSON array at `TOOLMARK_CVE_FILE`)
/// are appended, so a synced feed extends coverage without a rebuild.
fn ruleset() -> Vec<CveRule> {
    let mut rules: Vec<CveRule> = serde_json::from_str(EMBEDDED_JSON).unwrap_or_default();
    if let Some(path) = dguard::env_renamed("TOOLMARK_CVE_FILE", "SCOUT_CVE_FILE")
        && let Ok(text) = std::fs::read_to_string(&path)
        && let Ok(mut ext) = serde_json::from_str::<Vec<CveRule>>(&text)
    {
        rules.append(&mut ext);
    }
    rules
}

/// A small, high-confidence starter set of version-pinned CVEs for products the
/// fingerprinter commonly detects. Extend via TOOLMARK_CVE_FILE (a full feed export).
const EMBEDDED_JSON: &str = r#"[
  {
    "product": "Nginx",
    "cve": "CVE-2021-23017",
    "title": "nginx resolver off-by-one heap write",
    "severity": "high", "cvss": 7.7,
    "version_max_excl": "1.21.0",
    "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-23017"
  },
  {
    "product": "Apache HTTP Server",
    "cve": "CVE-2021-41773",
    "title": "Path traversal and file disclosure/RCE in Apache 2.4.49",
    "severity": "critical", "cvss": 9.8,
    "version_min": "2.4.49", "version_max_incl": "2.4.49",
    "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"
  },
  {
    "product": "Apache HTTP Server",
    "cve": "CVE-2021-42013",
    "title": "Path traversal and RCE in Apache 2.4.49/2.4.50",
    "severity": "critical", "cvss": 9.8,
    "version_min": "2.4.49", "version_max_incl": "2.4.50",
    "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-42013"
  },
  {
    "product": "OpenSSL",
    "cve": "CVE-2022-3602",
    "title": "X.509 email address 4-byte buffer overflow (punycode)",
    "severity": "high", "cvss": 7.5,
    "version_min": "3.0.0", "version_max_excl": "3.0.7",
    "reference": "https://nvd.nist.gov/vuln/detail/CVE-2022-3602"
  },
  {
    "product": "jQuery",
    "cve": "CVE-2020-11022",
    "title": "Cross-site scripting via jQuery HTML manipulation",
    "severity": "medium", "cvss": 6.1,
    "version_min": "1.2.0", "version_max_excl": "3.5.0",
    "reference": "https://nvd.nist.gov/vuln/detail/CVE-2020-11022"
  },
  {
    "product": "Bootstrap",
    "cve": "CVE-2019-8331",
    "title": "Cross-site scripting in Bootstrap tooltip/popover data-template",
    "severity": "medium", "cvss": 6.1,
    "version_min": "3.0.0", "version_max_excl": "3.4.1",
    "reference": "https://nvd.nist.gov/vuln/detail/CVE-2019-8331"
  },
  {
    "product": "Lodash",
    "cve": "CVE-2020-8203",
    "title": "Prototype pollution in lodash",
    "severity": "high", "cvss": 7.4,
    "version_max_excl": "4.17.19",
    "reference": "https://nvd.nist.gov/vuln/detail/CVE-2020-8203"
  }
]"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_parse_and_compare() {
        assert_eq!(parse_ver("1.21.0"), vec![1, 21, 0]);
        assert_eq!(parse_ver("v2.4.49p1"), vec![2, 4, 49]);
        assert_eq!(cmp_ver(&[1, 20, 2], &[1, 21, 0]), Ordering::Less);
        assert_eq!(cmp_ver(&[2, 4, 49], &[2, 4, 49]), Ordering::Equal);
        assert_eq!(cmp_ver(&[3, 0, 7], &[3, 0, 0]), Ordering::Greater);
    }

    #[test]
    fn matches_known_cves() {
        // nginx 1.20.2 is < 1.21.0 -> vulnerable to CVE-2021-23017.
        let m = match_cves("Nginx", "1.20.2");
        assert!(m.iter().any(|r| r.cve == "CVE-2021-23017"));
        // nginx 1.21.6 is patched.
        assert!(match_cves("Nginx", "1.21.6").is_empty());
        // Apache 2.4.49 -> both path-traversal CVEs.
        let a = match_cves("Apache HTTP Server", "2.4.49");
        assert!(a.iter().any(|r| r.cve == "CVE-2021-41773"));
        // No version -> no match (avoids false positives).
        assert!(match_cves("Nginx", "").is_empty());
        // Unknown product -> no match.
        assert!(match_cves("Caddy", "2.0.0").is_empty());
    }
}

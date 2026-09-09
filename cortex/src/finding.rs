//! One shape for every finding cortex emits, whatever produced it.
//!
//! Each producer used to hand-roll its own `json!` object and they drifted. The
//! template engine emitted `matched_at` and `template` but no `vuln_class`; the
//! injector emitted `vuln_class`, `param` and `location` but no `matched_at`;
//! GraphQL and the authz matrix each emitted a third mixture. A consumer then
//! had to know which half of the engine produced a finding before it could read
//! something as basic as where the bug is, which is why the asset graph carries
//! a `matched_at`-or-`url` fallback and why locations were being dropped on the
//! floor entirely by anything reading only one of the two.
//!
//! Everything now goes through `Finding`, so a finding always carries:
//!
//!   type, vuln_class, name, severity, confidence, description, source,
//!   target, url, matched_at
//!
//! and carries `method`, `param`, `location` and `template` whenever the
//! producer actually knows them (absent, never guessed).

use serde_json::{Map, Value, json};

/// Canonical class spelling: lowercase, underscore-separated.
///
/// The vocabulary is shared with the dashboard (`sqli`, `open_redirect`, `bola`)
/// so a class written one way here and another way there stops being possible.
pub fn normalise_class(class: &str) -> String {
    class
        .trim()
        .to_lowercase()
        .replace([' ', '-', '/'], "_")
        .replace("__", "_")
}

pub struct Finding {
    kind: &'static str,
    class: String,
    name: String,
    severity: String,
    /// Every producer confirms before it reports, so this is `confirmed`
    /// everywhere today; it stays a field because the shape promises it.
    confidence: &'static str,
    description: String,
    at: String,
    source: &'static str,
    method: Option<String>,
    param: Option<String>,
    location: Option<String>,
    template: Option<String>,
    extra: Map<String, Value>,
}

impl Finding {
    /// `at` is where the finding was confirmed: the full URL, or `host:port` for
    /// a non-HTTP service. It becomes `target`, `url` and `matched_at` at once,
    /// which is the whole point of this type.
    pub fn new(
        source: &'static str,
        class: &str,
        name: impl Into<String>,
        severity: impl Into<String>,
        at: impl Into<String>,
    ) -> Self {
        Self {
            kind: "vulnerability",
            class: normalise_class(class),
            name: name.into(),
            severity: severity.into(),
            confidence: "confirmed",
            description: String::new(),
            at: at.into(),
            source,
            method: None,
            param: None,
            location: None,
            template: None,
            extra: Map::new(),
        }
    }

    /// Not a vulnerability but still a finding: a WAF wall that makes the run
    /// inconclusive, for instance. Kept out of the vulnerability stream so a
    /// posture note is never counted as a bug.
    pub fn kind(mut self, kind: &'static str) -> Self {
        self.kind = kind;
        self
    }

    pub fn describe(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    pub fn method(mut self, method: impl Into<String>) -> Self {
        let m = method.into();
        if !m.is_empty() {
            self.method = Some(m.to_uppercase());
        }
        self
    }

    pub fn param(mut self, param: impl Into<String>) -> Self {
        let p = param.into();
        if !p.is_empty() {
            self.param = Some(p);
        }
        self
    }

    /// Where the payload went in: `query`, `path`, `header`, `body`, `graphql`,
    /// `endpoint` (the endpoint itself, no single injection point).
    pub fn location(mut self, location: &str) -> Self {
        if !location.is_empty() {
            self.location = Some(location.to_string());
        }
        self
    }

    pub fn template(mut self, template: impl Into<String>) -> Self {
        let t = template.into();
        if !t.is_empty() {
            self.template = Some(t);
        }
        self
    }

    /// Producer-specific evidence (the authz matrix, the identity a probe ran
    /// as). Never a substitute for the canonical keys above.
    pub fn with(mut self, key: &str, value: Value) -> Self {
        self.extra.insert(key.to_string(), value);
        self
    }

    pub fn build(self) -> Value {
        let mut o = Map::new();
        o.insert("type".into(), json!(self.kind));
        o.insert("vuln_class".into(), json!(self.class));
        o.insert("name".into(), json!(self.name));
        o.insert("severity".into(), json!(self.severity));
        o.insert("confidence".into(), json!(self.confidence));
        o.insert("description".into(), json!(self.description));
        o.insert("source".into(), json!(self.source));
        // The same place under all three names every consumer has ever used.
        o.insert("target".into(), json!(self.at));
        o.insert("url".into(), json!(self.at));
        o.insert("matched_at".into(), json!(self.at));
        if let Some(m) = self.method {
            o.insert("method".into(), json!(m));
        }
        if let Some(p) = self.param {
            o.insert("param".into(), json!(p));
        }
        if let Some(l) = self.location {
            o.insert("location".into(), json!(l));
        }
        if let Some(t) = self.template {
            o.insert("template".into(), json!(t));
        }
        for (k, v) in self.extra {
            o.insert(k, v);
        }
        Value::Object(o)
    }

    /// Wrapped in the daemon's stream envelope, ready to send.
    pub fn event(self) -> Value {
        json!({"type": "finding", "data": self.build()})
    }
}

/// The class a template finding belongs to, from its own metadata.
///
/// Template findings used to carry no class at all, so every consumer that
/// wanted one (dedupe, grouping, the benchmark scorer) re-derived it from the
/// template id with its own private lookup table, and each table was wrong in a
/// different way. The template already declares what it is in `info.tags`, so
/// read that instead of guessing from the id.
///
/// A known CVE stays classed `cve` rather than as its underlying bug type: the
/// CVE id in `template` is the precise identity, and the rest of the system
/// (answer keys, the dashboard) treats "a known, published vulnerability" as
/// its own class.
pub fn class_from_tags(tags: &str, template_id: &str, category: &str) -> String {
    let tags: Vec<String> = tags
        .split(',')
        .map(|t| t.trim().to_lowercase())
        .filter(|t| !t.is_empty())
        .collect();
    let has = |t: &str| tags.iter().any(|x| x == t);

    if template_id.to_uppercase().starts_with("CVE-") || has("cve") {
        return "cve".into();
    }

    // Specific bug classes before the generic ones: a template tagged
    // `ssti,injection,rce` is an SSTI finding, not an unspecified RCE.
    for (tag, class) in [
        ("sqli", "sqli"),
        ("sql-injection", "sqli"),
        ("nosql", "nosqli"),
        ("xss", "xss"),
        ("ssti", "ssti"),
        ("ssrf", "ssrf"),
        ("xxe", "xxe"),
        ("crlf", "crlf"),
        ("lfi", "lfi"),
        ("traversal", "traversal"),
        ("cmdi", "cmdi"),
        ("command-injection", "cmdi"),
        ("deserialization", "deserialization"),
        ("redirect", "open_redirect"),
        ("cors", "cors"),
        ("auth-bypass", "auth_bypass"),
        ("access-control", "access_control"),
        ("default-login", "default_login"),
        ("rce", "rce"),
    ] {
        if has(tag) {
            return class.into();
        }
    }

    for (tag, class) in [
        ("panel", "panel"),
        ("exposure", "exposure"),
        ("disclosure", "exposure"),
        ("misconfig", "misconfig"),
        ("waf", "waf"),
        ("tech", "tech"),
    ] {
        if has(tag) {
            return class.into();
        }
    }

    // Fall back to the pack directory the template lives in, which is always set.
    match category {
        "cves" => "cve",
        "exposures" => "exposure",
        "panels" => "panel",
        "technologies" => "tech",
        "default-logins" => "default_login",
        "misconfigurations" => "misconfig",
        "vulnerabilities" => "vuln",
        _ => "vuln",
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_finding_carries_the_same_locators() {
        let v = Finding::new(
            "cortex-inject",
            "SQLi",
            "SQL injection",
            "high",
            "http://h/a?b=1",
        )
        .method("get")
        .param("b")
        .location("query")
        .describe("d")
        .build();
        assert_eq!(v["vuln_class"], "sqli");
        assert_eq!(v["target"], "http://h/a?b=1");
        assert_eq!(v["url"], "http://h/a?b=1");
        assert_eq!(v["matched_at"], "http://h/a?b=1");
        assert_eq!(v["method"], "GET");
        assert_eq!(v["type"], "vulnerability");
    }

    #[test]
    fn unknown_fields_are_absent_not_empty() {
        let v = Finding::new("cortex", "exposure", "n", "info", "http://h/").build();
        assert!(v.get("param").is_none());
        assert!(v.get("location").is_none());
        assert!(v.get("template").is_none());
    }

    #[test]
    fn class_spelling_is_canonical() {
        assert_eq!(normalise_class("mass-assignment"), "mass_assignment");
        assert_eq!(normalise_class("Type-Confusion"), "type_confusion");
        assert_eq!(normalise_class("open_redirect"), "open_redirect");
    }

    #[test]
    fn template_class_comes_from_tags() {
        assert_eq!(
            class_from_tags("vuln,ssti,injection,rce", "ssti-x", "vulnerabilities"),
            "ssti"
        );
        assert_eq!(
            class_from_tags("cve,cve2021,rce", "CVE-2021-44228", "cves"),
            "cve"
        );
        assert_eq!(
            class_from_tags("exposure,git,source-code", "git-head", "exposures"),
            "exposure"
        );
        assert_eq!(
            class_from_tags("", "spring-actuator-env", "misconfigurations"),
            "misconfig"
        );
        // `credentials` is a modifier on an exposure ("this file holds secrets"),
        // not a default-login finding.
        assert_eq!(
            class_from_tags("exposure,npm,credentials", "npmrc", "exposures"),
            "exposure"
        );
        assert_eq!(
            class_from_tags(
                "default-login,tomcat,credentials",
                "tomcat-manager-default",
                "default-logins"
            ),
            "default_login"
        );
    }
}

//! Built-in web technology signatures + WAF/CDN passive detection.
//!
//! This is a curated, hand-rolled signature set (no external dataset) so it
//! carries no third-party data licensing. It is intentionally a superset-ready
//! shape: a fuller Wappalyzer-compatible dataset can be loaded at runtime later
//! (see docs/tier1-engines-plan.md section 2). Confidence is additive and capped,
//! versions are extracted where a source exposes them, and CPEs are emitted as
//! join keys for downstream CVE matching.

use regex::Regex;
use std::collections::HashSet;
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

enum Pat {
    /// (header-name-lowercase, value regex)
    Header(&'static str, Regex),
    /// cookie-name regex
    Cookie(Regex),
    /// meta generator content regex
    Meta(Regex),
    /// response-body regex
    Body(Regex),
}

struct Rule {
    name: &'static str,
    category: &'static str,
    /// CPE 2.3 template; "{}" is replaced with the detected version (or "*").
    cpe: &'static str,
    patterns: Vec<Pat>,
    /// Version extractor, run over the concatenated evidence blob.
    version: Option<Regex>,
    implies: &'static [&'static str],
}

fn h(name: &'static str, re: &str) -> Pat {
    Pat::Header(name, Regex::new(re).unwrap())
}
fn ck(re: &str) -> Pat {
    Pat::Cookie(Regex::new(re).unwrap())
}
fn mt(re: &str) -> Pat {
    Pat::Meta(Regex::new(re).unwrap())
}
fn bd(re: &str) -> Pat {
    Pat::Body(Regex::new(re).unwrap())
}
fn ver(re: &str) -> Option<Regex> {
    Regex::new(re).ok()
}

static RULES: LazyLock<Vec<Rule>> = LazyLock::new(build_rules);

fn build_rules() -> Vec<Rule> {
    vec![
        // --- Web servers ---
        Rule {
            name: "Nginx",
            category: "Web Server",
            cpe: "cpe:2.3:a:f5:nginx:{}:*:*:*:*:*:*:*",
            patterns: vec![h("server", r"(?i)nginx")],
            version: ver(r"(?i)nginx/([0-9.]+)"),
            implies: &[],
        },
        Rule {
            name: "Apache HTTP Server",
            category: "Web Server",
            cpe: "cpe:2.3:a:apache:http_server:{}:*:*:*:*:*:*:*",
            patterns: vec![h("server", r"(?i)apache")],
            version: ver(r"(?i)apache/([0-9.]+)"),
            implies: &[],
        },
        Rule {
            name: "Microsoft IIS",
            category: "Web Server",
            cpe: "cpe:2.3:a:microsoft:internet_information_services:{}:*:*:*:*:*:*:*",
            patterns: vec![h("server", r"(?i)microsoft-iis|(?i)\biis\b")],
            version: ver(r"(?i)iis/([0-9.]+)"),
            implies: &["ASP.NET"],
        },
        Rule {
            name: "OpenResty",
            category: "Web Server",
            cpe: "cpe:2.3:a:openresty:openresty:{}:*:*:*:*:*:*:*",
            patterns: vec![h("server", r"(?i)openresty")],
            version: ver(r"(?i)openresty/([0-9.]+)"),
            implies: &["Nginx"],
        },
        Rule {
            name: "LiteSpeed",
            category: "Web Server",
            cpe: "",
            patterns: vec![h("server", r"(?i)litespeed")],
            version: None,
            implies: &[],
        },
        Rule {
            name: "Apache Tomcat",
            category: "Web Server",
            cpe: "cpe:2.3:a:apache:tomcat:{}:*:*:*:*:*:*:*",
            patterns: vec![h("server", r"(?i)tomcat|coyote"), ck(r"(?i)^JSESSIONID$")],
            version: ver(r"(?i)tomcat/([0-9.]+)|coyote/([0-9.]+)"),
            implies: &["Java"],
        },
        Rule {
            name: "Jetty",
            category: "Web Server",
            cpe: "",
            patterns: vec![h("server", r"(?i)jetty")],
            version: ver(r"(?i)jetty\(?([0-9.]+)"),
            implies: &["Java"],
        },
        Rule {
            name: "Gunicorn",
            category: "Web Server",
            cpe: "",
            patterns: vec![h("server", r"(?i)gunicorn")],
            version: ver(r"(?i)gunicorn/([0-9.]+)"),
            implies: &["Python"],
        },
        Rule {
            name: "Kestrel",
            category: "Web Server",
            cpe: "",
            patterns: vec![h("server", r"(?i)kestrel")],
            version: None,
            implies: &["ASP.NET Core"],
        },
        Rule {
            name: "Werkzeug",
            category: "Web Server",
            cpe: "",
            patterns: vec![h("server", r"(?i)werkzeug")],
            version: ver(r"(?i)werkzeug/([0-9.]+)"),
            implies: &["Python", "Flask"],
        },
        // --- Languages / runtimes ---
        Rule {
            name: "PHP",
            category: "Language",
            cpe: "cpe:2.3:a:php:php:{}:*:*:*:*:*:*:*",
            patterns: vec![h("x-powered-by", r"(?i)php"), ck(r"(?i)^PHPSESSID$")],
            version: ver(r"(?i)php/([0-9.]+)"),
            implies: &[],
        },
        Rule {
            name: "ASP.NET",
            category: "Framework",
            cpe: "cpe:2.3:a:microsoft:asp.net:{}:*:*:*:*:*:*:*",
            patterns: vec![
                h("x-powered-by", r"(?i)asp\.net"),
                h("x-aspnet-version", r".+"),
                ck(r"(?i)^ASP\.NET_SessionId$"),
            ],
            version: ver(r"(?i)x-aspnet-version:?\s*([0-9.]+)"),
            implies: &[],
        },
        Rule {
            name: "ASP.NET Core",
            category: "Framework",
            cpe: "",
            patterns: vec![
                h("x-powered-by", r"(?i)asp\.net"),
                h("server", r"(?i)kestrel"),
            ],
            version: None,
            implies: &[],
        },
        // --- Backend frameworks ---
        Rule {
            name: "Express",
            category: "Framework",
            cpe: "cpe:2.3:a:openjsf:express:{}:*:*:*:*:node.js:*:*",
            patterns: vec![h("x-powered-by", r"(?i)express")],
            version: None,
            implies: &["Node.js"],
        },
        Rule {
            name: "Laravel",
            category: "Framework",
            cpe: "",
            patterns: vec![ck(r"(?i)^laravel_session$"), ck(r"(?i)^XSRF-TOKEN$")],
            version: None,
            implies: &["PHP"],
        },
        Rule {
            name: "Django",
            category: "Framework",
            cpe: "",
            patterns: vec![ck(r"(?i)^csrftoken$"), ck(r"(?i)^django")],
            version: None,
            implies: &["Python"],
        },
        Rule {
            name: "Flask",
            category: "Framework",
            cpe: "",
            patterns: vec![ck(r"(?i)^session$"), h("server", r"(?i)werkzeug")],
            version: None,
            implies: &["Python"],
        },
        Rule {
            name: "Ruby on Rails",
            category: "Framework",
            cpe: "",
            patterns: vec![ck(r"(?i)^_session_id$"), bd(r#"(?i)csrf-param"#)],
            version: None,
            implies: &["Ruby"],
        },
        Rule {
            name: "Spring",
            category: "Framework",
            cpe: "",
            patterns: vec![ck(r"(?i)^JSESSIONID$"), bd(r"(?i)org\.springframework")],
            version: None,
            implies: &["Java"],
        },
        // --- CMS ---
        Rule {
            name: "WordPress",
            category: "CMS",
            cpe: "cpe:2.3:a:wordpress:wordpress:{}:*:*:*:*:*:*:*",
            patterns: vec![
                mt(r"(?i)wordpress"),
                bd(r"(?i)/wp-content/|/wp-includes/"),
                ck(r"(?i)^wordpress_|^wp-settings"),
            ],
            version: ver(r"(?i)WordPress ([0-9.]+)"),
            implies: &["PHP", "MySQL"],
        },
        Rule {
            name: "Drupal",
            category: "CMS",
            cpe: "cpe:2.3:a:drupal:drupal:{}:*:*:*:*:*:*:*",
            patterns: vec![
                mt(r"(?i)drupal"),
                h("x-generator", r"(?i)drupal"),
                bd(r"(?i)/sites/all/|/sites/default/files|Drupal\.settings"),
            ],
            version: ver(r"(?i)Drupal ([0-9]+)"),
            implies: &["PHP"],
        },
        Rule {
            name: "Joomla",
            category: "CMS",
            cpe: "cpe:2.3:a:joomla:joomla\\!:{}:*:*:*:*:*:*:*",
            patterns: vec![
                mt(r"(?i)joomla"),
                bd(r"(?i)/media/jui/|/media/system/js/|option=com_"),
            ],
            version: ver(r"(?i)Joomla!?\s*([0-9.]+)"),
            implies: &["PHP"],
        },
        Rule {
            name: "Magento",
            category: "CMS",
            cpe: "",
            patterns: vec![
                ck(r"(?i)^X-Magento"),
                bd(r"(?i)Mage\.Cookies|/static/version|/mage/"),
            ],
            version: None,
            implies: &["PHP"],
        },
        Rule {
            name: "Ghost",
            category: "CMS",
            cpe: "",
            patterns: vec![mt(r"(?i)ghost"), bd(r"(?i)content=.Ghost")],
            version: ver(r"(?i)Ghost ([0-9.]+)"),
            implies: &["Node.js"],
        },
        // --- JS frameworks / libraries ---
        Rule {
            name: "Next.js",
            category: "JavaScript Framework",
            cpe: "",
            patterns: vec![
                h("x-powered-by", r"(?i)next\.js"),
                bd(r"(?i)/_next/|__NEXT_DATA__"),
            ],
            version: ver(r"(?i)next\.js\s*([0-9.]+)"),
            implies: &["React", "Node.js"],
        },
        Rule {
            name: "Nuxt.js",
            category: "JavaScript Framework",
            cpe: "",
            patterns: vec![bd(r"(?i)__NUXT__|/_nuxt/")],
            version: None,
            implies: &["Vue.js", "Node.js"],
        },
        Rule {
            name: "React",
            category: "JavaScript Framework",
            cpe: "",
            patterns: vec![bd(
                r"(?i)data-reactroot|react(?:-dom)?(?:\.production)?\.min\.js|__REACT_DEVTOOLS",
            )],
            version: None,
            implies: &[],
        },
        Rule {
            name: "Vue.js",
            category: "JavaScript Framework",
            cpe: "",
            patterns: vec![bd(
                r#"(?i)data-v-[0-9a-f]{6,8}|vue(?:\.runtime)?(?:\.min)?\.js|id="app""#,
            )],
            version: None,
            implies: &[],
        },
        Rule {
            name: "Angular",
            category: "JavaScript Framework",
            cpe: "",
            patterns: vec![bd(r"(?i)ng-version|_nghost|angular(?:\.min)?\.js")],
            version: ver(r#"(?i)ng-version="([0-9.]+)""#),
            implies: &[],
        },
        Rule {
            name: "jQuery",
            category: "JavaScript Library",
            cpe: "cpe:2.3:a:jquery:jquery:{}:*:*:*:*:*:*:*",
            patterns: vec![bd(r"(?i)jquery[.-]([0-9.]+)(?:\.min)?\.js|jQuery v[0-9.]+")],
            version: ver(r"(?i)jquery[.-]([0-9.]+)|jQuery v([0-9.]+)"),
            implies: &[],
        },
        Rule {
            name: "Bootstrap",
            category: "UI Framework",
            cpe: "",
            patterns: vec![bd(
                r"(?i)bootstrap(?:\.min)?\.(?:css|js)|class=.(?:container|navbar)-",
            )],
            version: ver(r"(?i)bootstrap[.-v]*([0-9.]+)(?:\.min)?\.(?:css|js)"),
            implies: &[],
        },
        // --- CDN / edge (also surfaced separately by waf_cdn) ---
        Rule {
            name: "Cloudflare",
            category: "CDN",
            cpe: "",
            patterns: vec![h("server", r"(?i)cloudflare"), h("cf-ray", r".+")],
            version: None,
            implies: &[],
        },
        Rule {
            name: "Varnish",
            category: "Caching",
            cpe: "",
            patterns: vec![h("via", r"(?i)varnish"), h("x-varnish", r".+")],
            version: None,
            implies: &[],
        },
        // --- Hosted platforms ---
        Rule {
            name: "Shopify",
            category: "Ecommerce",
            cpe: "",
            patterns: vec![
                h("x-shopify-stage", r".+"),
                h("x-sorting-hat-shopid", r".+"),
                bd(r"(?i)cdn\.shopify\.com"),
            ],
            version: None,
            implies: &[],
        },
        Rule {
            name: "Wix",
            category: "CMS",
            cpe: "",
            patterns: vec![
                h("x-wix-request-id", r".+"),
                bd(r"(?i)static\.wixstatic\.com"),
            ],
            version: None,
            implies: &[],
        },
        Rule {
            name: "Squarespace",
            category: "CMS",
            cpe: "",
            patterns: vec![
                h("server", r"(?i)squarespace"),
                bd(r"(?i)static1\.squarespace\.com"),
            ],
            version: None,
            implies: &[],
        },
    ]
}

/// Run the signature engine over a page's collected signals.
pub fn detect(headers: &[(String, String)], cookies: &[String], body: &str) -> Vec<Detection> {
    let server = header_val(headers, "server").unwrap_or_default();
    let powered = header_val(headers, "x-powered-by").unwrap_or_default();
    let generator = extract_meta_generator(body).unwrap_or_default();
    let body_head = first_n(body, 60_000);

    let mut out: Vec<Detection> = Vec::new();
    for rule in RULES.iter() {
        let mut conf: u32 = 0;
        let mut evidence: Vec<String> = Vec::new();
        for pat in &rule.patterns {
            match pat {
                Pat::Header(name, re) => {
                    if let Some(v) = header_val(headers, name)
                        && re.is_match(&v)
                    {
                        conf += 50;
                        evidence.push(format!("header {}: {}", name, truncate(&v, 80)));
                    }
                }
                Pat::Cookie(re) => {
                    for c in cookies {
                        let cn = c.split(&['=', ';'][..]).next().unwrap_or("").trim();
                        if re.is_match(cn) {
                            conf += 45;
                            evidence.push(format!("cookie {cn}"));
                            break;
                        }
                    }
                }
                Pat::Meta(re) => {
                    if !generator.is_empty() && re.is_match(&generator) {
                        conf += 60;
                        evidence.push(format!("meta generator: {}", truncate(&generator, 80)));
                    }
                }
                Pat::Body(re) => {
                    if re.is_match(&body_head) {
                        conf += 25;
                        evidence.push("body pattern".to_string());
                    }
                }
            }
        }
        if conf == 0 {
            continue;
        }
        let blob = format!("{server} {powered} {generator} {body_head}");
        let version = rule
            .version
            .as_ref()
            .and_then(|re| re.captures(&blob))
            .and_then(|c| (1..c.len()).filter_map(|i| c.get(i)).next())
            .map(|m| m.as_str().to_string());
        let cpe = if rule.cpe.is_empty() {
            String::new()
        } else if rule.cpe.contains("{}") {
            rule.cpe.replace("{}", version.as_deref().unwrap_or("*"))
        } else {
            rule.cpe.to_string()
        };
        out.push(Detection {
            name: rule.name.to_string(),
            category: rule.category.to_string(),
            version,
            cpe,
            confidence: conf.min(100) as u8,
            evidence,
        });
    }

    // One-pass `implies`: add implied techs not already directly detected.
    let present: HashSet<String> = out.iter().map(|d| d.name.clone()).collect();
    let mut implied: Vec<Detection> = Vec::new();
    for d in &out {
        if let Some(rule) = RULES.iter().find(|r| r.name == d.name) {
            for imp in rule.implies {
                if !present.contains(*imp) && !implied.iter().any(|x| x.name == *imp) {
                    implied.push(Detection {
                        name: (*imp).to_string(),
                        category: "Implied".to_string(),
                        version: None,
                        cpe: String::new(),
                        confidence: 30,
                        evidence: vec![format!("implied by {}", d.name)],
                    });
                }
            }
        }
    }
    out.extend(implied);
    out
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

static META_GEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)<meta[^>]+name\s*=\s*["']generator["'][^>]+content\s*=\s*["']([^"']+)["']"#)
        .unwrap()
});
static META_GEN_RE2: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)<meta[^>]+content\s*=\s*["']([^"']+)["'][^>]+name\s*=\s*["']generator["']"#)
        .unwrap()
});

pub fn extract_meta_generator(body: &str) -> Option<String> {
    META_GEN_RE
        .captures(body)
        .or_else(|| META_GEN_RE2.captures(body))
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
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

fn first_n(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        // Respect char boundaries.
        let mut end = n;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        s[..end].to_string()
    }
}

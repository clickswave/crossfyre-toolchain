//! The proof a finding is kept with, so that it can be checked again without the scan:
//! the requests that found it, in order, the matchers that judge the answer and which of
//! them fired on what, a hash of the answer, and the versions that ran it.
//!
//! A proof keeps no secret. The scan's own credential goes on the client, not in the
//! requests, and the proof names only the slots it fills (`auth.cookie`,
//! `auth.header:<name>`). A header whose name marks a credential is a slot too, every
//! URL is made safe as a finding's are, and so is the evidence, so that the proof can
//! travel with the finding to Cloud. A replay fills the slots from what it is given and
//! refuses a proof with one it cannot fill.

use crate::template::Matcher;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The proof format this engine writes and replays.
pub const FORMAT: u32 = 1;

/// The most a proof may take, as JSON: what is past it is evidence, cut to fit.
pub const MAX_BYTES: usize = 64 * 1024;

/// The most one piece of evidence keeps.
const EVIDENCE_CHARS: usize = 512;

/// What a proof is of: a template's check, or one of the passive header checks on the
/// target's base response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Template,
    Header,
}

/// One request a check sent, as it is replayed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sent {
    pub method: String,
    pub url: String,
    /// Its own header lines, name and value, beside the client's; a credential's value is
    /// a slot.
    pub fields: Vec<(String, String)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// Sent over a raw socket with its request-target as written.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub raw: bool,
}

/// A matcher that held, and what it held on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fired {
    /// The matcher's type: word, regex, status, size, dsl, or, for a header check,
    /// header, and for an out-of-band check, callback.
    pub matcher: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub part: String,
    pub evidence: String,
}

/// A finding's proof.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Proof {
    pub format: u32,
    /// The engine and its version.
    pub engine: String,
    /// Where the check came from: built in, the pack as plessor read it, or a folder.
    pub pack: String,
    pub kind: Kind,
    /// The template's id, or the header check's.
    pub check: String,
    pub requests: Vec<Sent>,
    /// The template request's matchers, so that a replay judges by the same rule.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matchers: Vec<Matcher>,
    #[serde(default = "and", skip_serializing_if = "is_and")]
    pub condition: String,
    pub fired: Vec<Fired>,
    /// The status of the answer that confirmed it, and the SHA-256 of its body.
    pub status: u16,
    pub response_sha256: String,
    /// What a replay must be given that the proof does not keep.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub slots: Vec<String>,
    /// Evidence was cut for the proof to fit in [`MAX_BYTES`].
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub trimmed: bool,
}

fn and() -> String {
    "and".to_string()
}

fn is_and(c: &String) -> bool {
    c == "and"
}

/// Where a scan's checks came from, and the slots its credential fills, for the proofs
/// of what it finds.
pub struct Ctx {
    pub engine: String,
    pub slots: Vec<String>,
}

impl Ctx {
    /// For a scan sent with `auth`: the slots it fills, by name, never by value.
    pub fn new(auth: Option<&transport::AuthSpec>) -> Self {
        let mut slots = Vec::new();
        if let Some(auth) = auth.filter(|a| a.is_meaningful()) {
            if !auth.cookies.trim().is_empty() {
                slots.push("auth.cookie".to_string());
            }
            let mut names: Vec<&String> = auth.headers.keys().collect();
            names.sort();
            for name in names {
                slots.push(format!("auth.header:{name}"));
            }
        }
        Self {
            engine: format!("plessor {}", env!("CARGO_PKG_VERSION")),
            slots,
        }
    }
}

/// The slot an out-of-band host is kept as.
pub const OAST_SLOT: &str = "{{slot:oast}}";

impl Proof {
    /// A proof of `check` from `pack`, by what was `sent`, judged by `matchers` under
    /// `condition`, which `fired` on an answer of `status` with `body`. Made safe to keep,
    /// and cut to fit.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ctx: &Ctx,
        pack: &str,
        kind: Kind,
        check: &str,
        sent: Vec<Sent>,
        matchers: Vec<Matcher>,
        condition: &str,
        fired: Vec<Fired>,
        status: u16,
        body: &str,
    ) -> Self {
        let mut slots = ctx.slots.clone();
        let requests = sent.into_iter().map(|s| kept(s, &mut slots)).collect();
        let mut proof = Proof {
            format: FORMAT,
            engine: ctx.engine.clone(),
            pack: pack.to_string(),
            kind,
            check: check.to_string(),
            requests,
            matchers,
            condition: if condition.eq_ignore_ascii_case("or") {
                "or".to_string()
            } else {
                "and".to_string()
            },
            fired: fired
                .into_iter()
                .map(|f| Fired {
                    evidence: evidence(&f.evidence),
                    ..f
                })
                .collect(),
            status,
            response_sha256: sha256(body),
            slots,
            trimmed: false,
        };
        proof.fit();
        proof
    }

    /// The proof as JSON, its size in bytes.
    pub fn size(&self) -> usize {
        serde_json::to_vec(self).map_or(usize::MAX, |b| b.len())
    }

    /// Cut the evidence, longest first, until the proof is within [`MAX_BYTES`].
    fn fit(&mut self) {
        while self.size() > MAX_BYTES {
            let Some(longest) = self
                .fired
                .iter_mut()
                .filter(|f| !f.evidence.is_empty())
                .max_by_key(|f| f.evidence.len())
            else {
                return;
            };
            let keep = longest.evidence.chars().count() / 2;
            longest.evidence = longest.evidence.chars().take(keep).collect();
            self.trimmed = true;
        }
    }
}

/// `sent` as a proof keeps it: each URL made safe, a credential header's value and the
/// out-of-band host slots, named in `slots`.
fn kept(mut sent: Sent, slots: &mut Vec<String>) -> Sent {
    let safe = cfx_db::scans::safe_url(&sent.url);
    if safe != sent.url {
        add(slots, "url");
    }
    sent.url = safe;
    for (name, value) in &mut sent.fields {
        if cfx_db::scans::secret_name(name) {
            let slot = format!("header:{name}");
            *value = format!("{{{{slot:{slot}}}}}");
            add(slots, &slot);
        } else {
            *value = cfx_db::scans::safe_text(value);
        }
    }
    if let Some(body) = &mut sent.body {
        let safe = cfx_db::scans::safe_text(body);
        if safe != *body {
            add(slots, "body");
        }
        *body = safe;
    }
    sent
}

fn add(slots: &mut Vec<String>, slot: &str) {
    if !slots.iter().any(|s| s == slot) {
        slots.push(slot.to_string());
    }
}

/// Evidence as a proof keeps it: at most [`EVIDENCE_CHARS`] characters, with every URL
/// made safe and the value of anything named as a credential left out, so that what a
/// target exposed is shown and not kept.
pub fn evidence(text: &str) -> String {
    static NAMED: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(
            r#"(["']?)([A-Za-z0-9_.\-]+)(["']?\s*[:=]\s*["']?)([^"'\s&,;<>\[][^"'\s&,;<>]*)"#,
        )
        .expect("the pattern compiles")
    });
    let short: String = text.chars().take(EVIDENCE_CHARS).collect();
    let safe = cfx_db::scans::safe_text(&short);
    NAMED
        .replace_all(&safe, |c: &regex::Captures| {
            if cfx_db::scans::secret_name(&c[2]) {
                format!("{}{}{}[not kept]", &c[1], &c[2], &c[3])
            } else {
                c[0].to_string()
            }
        })
        .into_owned()
}

/// The SHA-256 of `body`, in hex.
pub fn sha256(body: &str) -> String {
    format!("{:x}", Sha256::digest(body.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> Ctx {
        Ctx::new(None)
    }

    fn sent(url: &str, fields: &[(&str, &str)]) -> Sent {
        Sent {
            method: "GET".into(),
            url: url.into(),
            fields: fields
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: None,
            raw: false,
        }
    }

    /// A scan's credential is named as slots and never kept, and neither is a credential
    /// header's value, a URL's secret, or a credential the target's answer showed.
    #[test]
    fn a_proof_of_an_authenticated_scan_keeps_no_secret() {
        let auth: transport::AuthSpec = serde_json::from_value(serde_json::json!({
            "cookies": "session=s3cr3t-cookie-value",
            "headers": {"Authorization": "Bearer t0ken-value-123", "X-Api-Key": "k3y-value"},
        }))
        .unwrap();
        let ctx = Ctx::new(Some(&auth));
        let proof = Proof::new(
            &ctx,
            "compiled in",
            Kind::Template,
            "exposed-env",
            vec![sent(
                "https://user:pa55word-value@app.test/.env?access_token=url-t0ken-value&x=1",
                &[
                    ("Authorization", "Basic YWRtaW46cGFzc3dvcmQtdmFsdWU="),
                    ("User-Agent", "probe"),
                ],
            )],
            Vec::new(),
            "and",
            vec![Fired {
                matcher: "regex".into(),
                part: "body".into(),
                evidence: "DB_PASSWORD=hunter2-value\nAPP_SECRET: 'also-secret-value'\n\"api_token\": \"json-t0ken-value\"".into(),
            }],
            200,
            "DB_PASSWORD=hunter2-value",
        );
        let kept = serde_json::to_string(&proof).unwrap();
        for secret in [
            "s3cr3t-cookie-value",
            "t0ken-value-123",
            "k3y-value",
            "pa55word-value",
            "url-t0ken-value",
            "YWRtaW46cGFzc3dvcmQtdmFsdWU=",
            "hunter2-value",
            "also-secret-value",
            "json-t0ken-value",
        ] {
            assert!(!kept.contains(secret), "{secret} kept in {kept}");
        }
        assert_eq!(
            proof.slots,
            [
                "auth.cookie",
                "auth.header:Authorization",
                "auth.header:X-Api-Key",
                "url",
                "header:Authorization"
            ]
        );
        assert_eq!(
            proof.requests[0].fields[1],
            ("User-Agent".into(), "probe".into())
        );
        assert!(proof.fired[0].evidence.contains("DB_PASSWORD=[not kept]"));
        // Kept by the daemon as a finding is, it is the same.
        assert_eq!(
            cfx_db::scans::safe_json(&serde_json::to_value(&proof).unwrap()),
            serde_json::to_value(&proof).unwrap()
        );
    }

    /// A proof past the size it may take keeps its requests and cuts its evidence, and
    /// says so.
    #[test]
    fn a_proof_too_large_cuts_its_evidence_and_says_so() {
        let fired = |n: usize| {
            (0..n)
                .map(|i| Fired {
                    matcher: "word".into(),
                    part: "body".into(),
                    evidence: format!("{i}{}", "x".repeat(600)),
                })
                .collect::<Vec<_>>()
        };
        let small = Proof::new(
            &ctx(),
            "built in",
            Kind::Template,
            "t",
            vec![sent("http://h/", &[])],
            Vec::new(),
            "and",
            fired(2),
            200,
            "",
        );
        assert!(!small.trimmed);
        let large = Proof::new(
            &ctx(),
            "built in",
            Kind::Template,
            "t",
            vec![sent("http://h/", &[])],
            Vec::new(),
            "and",
            fired(400),
            200,
            "",
        );
        assert!(large.trimmed);
        assert!(large.size() <= MAX_BYTES, "{}", large.size());
        assert_eq!(large.requests[0].url, "http://h/");
        assert_eq!(large.fired.len(), 400);
    }

    /// The answer's body is kept as its hash, and an answer of another body has another.
    #[test]
    fn the_answer_is_kept_as_its_hash() {
        assert_eq!(
            sha256("root:x:0:0:"),
            format!("{:x}", Sha256::digest(b"root:x:0:0:"))
        );
        assert_ne!(sha256("a"), sha256("b"));
    }
}

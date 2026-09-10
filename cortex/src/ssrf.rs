//! SSRF that reads back, and where it leads.
//!
//! The out-of-band check in `inject` proves a server made a request. That is the
//! right oracle for a blind fetch and it has one blind spot, which happens to
//! contain most of the impact: a callback can only arrive if the server can
//! reach the public internet. An SSRF that reaches ONLY internal addresses -
//! `127.0.0.1`, the private ranges, the cloud metadata service - produces no
//! callback at all, so the most dangerous version of this bug is the one that
//! looks clean.
//!
//! # Reading the fetch back
//!
//! When the application returns what it fetched, no listener is needed. Point
//! the parameter at a page of the target itself, and if that page's content
//! appears in the answer, the server fetched a URL we chose and handed us the
//! body. That works entirely inside the target's own network, which is exactly
//! where the OAST check cannot go.
//!
//! The canary is a page we fetched ourselves first, so we know what it says
//! before we ask the server to say it. The token is drawn from that page's own
//! text; the payload contains a URL and nothing else, so a reflected parameter
//! cannot produce it.
//!
//! A control follows: the same parameter pointed at a closed internal port. That
//! answer must NOT carry the token. Without it, an application that echoes an
//! entire response body for any input at all would read as SSRF.
//!
//! # Where it leads
//!
//! Only once a fetch has been confirmed and read back is the escalation worth
//! sending, and then it is one request per address. The cloud metadata services
//! answer on well-known addresses with unmistakable content, and reaching one of
//! them turns "the server makes requests for me" into "the server will hand me
//! its role credentials", which is a different conversation with a customer.
//!
//! Nothing here fetches a credential. The probe asks the metadata tree for its
//! INDEX and reports which branches exist, including
//! `iam/security-credentials/`, by name. Proving the door is unlocked is the
//! job; walking through it is not, and a scanner holding somebody's live AWS
//! session keys in a findings database is a worse problem than the one it found.

use serde_json::Value;

/// Internal addresses worth one request each, once a fetch is confirmed.
pub struct Internal {
    pub label: &'static str,
    pub url: &'static str,
    /// Extra request headers the service requires before it will answer. GCP
    /// and Azure both refuse without one, which is precisely why an SSRF that
    /// forwards headers is worth distinguishing from one that does not.
    pub headers: &'static [(&'static str, &'static str)],
    /// Strings that only this service's index page produces.
    pub signature: &'static [&'static str],
}

pub const INTERNAL: &[Internal] = &[
    Internal {
        label: "AWS EC2 instance metadata (IMDSv1)",
        url: "http://169.254.169.254/latest/meta-data/",
        headers: &[],
        // The index is a newline-separated listing. These entries appear on
        // every instance and nowhere else.
        signature: &["ami-id", "instance-id", "iam/", "hostname"],
    },
    Internal {
        label: "GCP compute metadata",
        url: "http://metadata.google.internal/computeMetadata/v1/instance/",
        headers: &[("Metadata-Flavor", "Google")],
        signature: &["service-accounts/", "machine-type", "zone"],
    },
    Internal {
        label: "Azure instance metadata",
        url: "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        headers: &[("Metadata", "true")],
        signature: &["\"azEnvironment\"", "\"vmId\"", "\"resourceGroupName\""],
    },
    Internal {
        label: "Kubernetes API server",
        url: "https://kubernetes.default.svc/api",
        headers: &[],
        signature: &[
            "\"serverAddressByClientCIDRs\"",
            "\"kind\": \"APIVersions\"",
        ],
    },
];

/// A closed port on the loopback interface. The control for the reflected
/// oracle: a fetch that cannot succeed must not produce the canary token.
pub const CLOSED_INTERNAL: &str = "http://127.0.0.1:1/";

/// How many of a service's signature strings must appear before we believe it.
///
/// More than one, because single tokens are not rare: a page that happens to
/// contain the word "zone" is not GCP metadata. Requiring two independent
/// markers from the same index is what makes this confirm rather than guess.
pub const SIGNATURE_HITS: usize = 2;

/// Which internal service, if any, this response body came from.
pub fn identify(body: &str) -> Option<&'static Internal> {
    let b = body.to_lowercase();
    INTERNAL.iter().find(|s| {
        s.signature
            .iter()
            .filter(|m| b.contains(&m.to_lowercase()))
            .count()
            >= SIGNATURE_HITS
    })
}

/// Distinctive strings from a page we fetched ourselves, to look for in what
/// the server fetches on our behalf. Best candidate first.
///
/// Several, not one, because the caller has to discard any candidate that
/// already appears in the endpoint's ordinary answer - site-wide chrome would
/// otherwise make the canary match a response nobody fetched anything for - and
/// discarding the only candidate means the check silently does not run.
///
/// Candidates are drawn from the page's visible TEXT, with markup removed.
/// Markup is the wrong source because every page on a site shares it, and a
/// token made of it would collide with the baseline on the first try.
pub fn canary_tokens(body: &str) -> Vec<String> {
    let text = visible_text(body);
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();

    // Windows of running text, taken from the middle outwards: headers and
    // navigation live at the edges and are the same on every page.
    const WINDOW: usize = 40;
    if chars.len() >= WINDOW {
        let mid = chars.len() / 2;
        for start in [mid, chars.len() / 4, 0] {
            let start = start.min(chars.len() - WINDOW);
            let w: String = chars[start..start + WINDOW].iter().collect();
            let w = w.trim().to_string();
            if w.len() >= 24 && !out.contains(&w) {
                out.push(w);
            }
        }
    }

    // Long individual words, as a fallback for a page with almost no prose.
    let mut words: Vec<&str> = text
        .split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '-'))
        .filter(|w| {
            // Long enough to be distinctive, and not something that changes
            // between two requests: a hex session token would compare this
            // fetch against the next one's.
            w.len() >= 10
                && w.len() <= 60
                && !w.chars().all(|c| c.is_ascii_hexdigit())
                && !w.chars().all(|c| c.is_ascii_digit())
        })
        .collect();
    words.sort_by_key(|w| std::cmp::Reverse(w.len()));
    for w in words.into_iter().take(4) {
        let w = w.to_string();
        if !out.contains(&w) {
            out.push(w);
        }
    }
    out
}

/// A page with its tags taken out and its whitespace collapsed.
fn visible_text(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut in_tag = false;
    let mut last_space = true;
    for c in body.chars() {
        match c {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                if !last_space {
                    out.push(' ');
                    last_space = true;
                }
            }
            _ if in_tag => {}
            c if c.is_whitespace() => {
                if !last_space {
                    out.push(' ');
                    last_space = true;
                }
            }
            c => {
                out.push(c);
                last_space = false;
            }
        }
    }
    out.trim().to_string()
}

/// A confirmed reach into the target's own network, ready to attach to a
/// finding.
pub fn reach_note(hit: &Internal) -> Value {
    serde_json::json!({
        "service": hit.label,
        "url": hit.url,
        "headers_required": hit.headers.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aws_metadata_index_is_recognised() {
        let body = "ami-id\nami-launch-index\nhostname\niam/\ninstance-id\n";
        assert_eq!(identify(body).unwrap().label, INTERNAL[0].label);
    }

    #[test]
    fn one_word_in_common_is_not_a_cloud() {
        // A page about availability zones is not GCP metadata.
        assert!(identify("Choose your zone from the list below.").is_none());
        // Nor is an ordinary error page anything at all.
        assert!(identify("<html><h1>502 Bad Gateway</h1></html>").is_none());
    }

    #[test]
    fn azure_needs_two_of_its_own_keys() {
        assert!(identify(r#"{"vmId":"x"}"#).is_none());
        assert!(identify(r#"{"azEnvironment":"AzurePublicCloud","vmId":"x"}"#).is_some());
    }

    #[test]
    fn canaries_come_from_the_text_not_the_markup() {
        let page = "<html><head><title>Meridian Provisioning Console</title></head><body>\
                    <p>Welcome to the internal provisioning console for warehouse operators.</p>\
                    </body></html>";
        let toks = canary_tokens(page);
        assert!(!toks.is_empty(), "no canary from a page full of prose");
        for t in &toks {
            assert!(!t.contains('<') && !t.contains('>'), "{t:?} carries markup");
            assert!(t.len() >= 10, "{t:?} is too short to mean anything");
        }
    }

    #[test]
    fn there_is_more_than_one_candidate_to_fall_back_to() {
        let page = "<html><body><h1>Quarterly Reconciliation</h1><p>The settlement ledger for \
                    the northern distribution region is reconciled every fortnight by the \
                    operations desk.</p></body></html>";
        assert!(
            canary_tokens(page).len() >= 2,
            "one candidate means the check stops the first time it collides with the baseline"
        );
    }

    #[test]
    fn a_value_that_changes_every_request_is_not_offered_as_a_word() {
        // The hex token would compare this request's value against the next
        // one's. It is not among the word candidates.
        let toks = canary_tokens("<input value='9f2c4b1ae77d0031bb45cc9012aa77de'>");
        assert!(!toks.iter().any(|t| t == "9f2c4b1ae77d0031bb45cc9012aa77de"));
    }
}

//! Cert Spotter (SSLMate) certificate-transparency source.
//!
//! Reads the same CT logs crt.sh does, but from an independent operator with a
//! JSON API that answers in well under a second. crt.sh is the better-known
//! source and returns more history, but it is also regularly slow or down, and a
//! passive enum with one CT source is a passive enum with one point of failure.
//!
//! The unauthenticated endpoint is rate limited per IP (a handful of queries a
//! minute at time of writing). That is fine as a second opinion alongside crt.sh
//! and not fine as a sole dependency, which is exactly how the caller uses it:
//! every source is best-effort and the results are unioned.
//!
//! Setting `CERTSPOTTER_TOKEN` sends an API key, which lifts the limit. Absent,
//! we query anonymously and accept the throttling.

use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;

#[derive(Deserialize)]
struct Issuance {
    #[serde(default)]
    dns_names: Vec<String>,
}

pub async fn fetch(
    reqwest_client: &Client,
    domain: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let url = format!(
        "https://api.certspotter.com/v1/issuances?domain={domain}\
         &include_subdomains=true&expand=dns_names"
    );

    let mut req = reqwest_client.get(&url);
    if let Ok(token) = std::env::var("CERTSPOTTER_TOKEN")
        && !token.trim().is_empty()
    {
        req = req.bearer_auth(token.trim());
    }
    let response = req.send().await?;

    // 429 is the documented throttle response and is expected on the anonymous
    // endpoint. Returning an empty set rather than an error keeps it a
    // best-effort source: the caller unions what every provider managed to
    // return and should not lose crt.sh's results because this one was busy.
    if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        return Ok(vec![]);
    }
    if !response.status().is_success() {
        return Ok(vec![]);
    }

    let body: Vec<Issuance> = response.json().await?;
    let dot_suffix = format!(".{domain}");
    let mut unique: HashSet<String> = HashSet::new();

    for issuance in body {
        for raw in issuance.dns_names {
            let host = raw.trim().trim_start_matches("*.").to_lowercase();
            if host.is_empty() {
                continue;
            }
            // Return the label prefix, matching what crt.sh's provider returns,
            // so passive_scan can reconstruct "<prefix>.<domain>" uniformly and
            // does not need to know which source a name came from.
            if let Some(stripped) = host.strip_suffix(&dot_suffix)
                && !stripped.is_empty()
                && stripped != "*"
            {
                unique.insert(stripped.to_string());
            }
        }
    }

    Ok(unique.into_iter().collect())
}

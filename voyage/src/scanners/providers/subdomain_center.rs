use reqwest::Client;
use std::collections::HashSet;

pub async fn fetch(
    reqwest_client: &Client,
    domain: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let url = format!("https://api.subdomain.center/?domain={domain}");
    // A non-2xx is an error so the caller logs it as a warning: the keyless API
    // rate-limits, and a 429 should not look like a silent empty result.
    let response = reqwest_client.get(&url).send().await?.error_for_status()?;
    let body = response.text().await?;

    Ok(parse(&body, domain)?)
}

/// Extract the label prefixes of `domain`'s subdomains from a response, which
/// is a JSON array of hostnames.
fn parse(body: &str, domain: &str) -> Result<Vec<String>, serde_json::Error> {
    let hosts: Vec<String> = serde_json::from_str(body)?;
    let dot_suffix = format!(".{domain}");
    let mut unique_subdomains = HashSet::new();

    for host in hosts.into_iter().map(|h| h.to_lowercase()) {
        // Keep only real subdomains of the target (skip the apex and
        // unrelated names like "notexample.com" that merely end in it).
        if let Some(stripped) = host.strip_suffix(&dot_suffix)
            && !stripped.is_empty()
        {
            unique_subdomains.insert(stripped.to_string());
        }
    }

    Ok(unique_subdomains.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::parse;

    // A real response for `rust-lang.org`, cut down to a few of its entries.
    const SAMPLE: &str = r#"[
        "triagebot.infra.rust-lang.org",
        "www.ci-artifacts.rust-lang.org",
        "triagebot.infra.rust-lang.org",
        "highfive.infra.rust-lang.org"
    ]"#;

    #[test]
    fn parse_keeps_unique_subdomain_prefixes_of_a_saved_response() {
        let mut prefixes = parse(SAMPLE, "rust-lang.org").unwrap();
        prefixes.sort();
        assert_eq!(
            prefixes,
            ["highfive.infra", "triagebot.infra", "www.ci-artifacts"]
        );
    }

    #[test]
    fn parse_lowercases_and_skips_the_apex_and_look_alikes() {
        let body = r#"[
            "API.Example.com",
            "a.b.example.com",
            "example.com",
            "notexample.com"
        ]"#;
        let mut prefixes = parse(body, "example.com").unwrap();
        prefixes.sort();
        assert_eq!(prefixes, ["a.b", "api"]);
    }

    #[test]
    fn parse_rejects_a_non_array_body() {
        assert!(parse(r#"{"error": "rate limited"}"#, "example.com").is_err());
    }
}

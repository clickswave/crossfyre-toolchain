use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;

#[derive(Deserialize)]
struct Response {
    passive_dns: Vec<PassiveDnsRecord>,
}

#[derive(Deserialize)]
struct PassiveDnsRecord {
    hostname: String,
}

pub async fn fetch(
    reqwest_client: &Client,
    domain: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let url = format!("https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns");

    let response = reqwest_client.get(&url).send().await?;

    if !response.status().is_success() {
        return Ok(vec![]);
    }

    let body = response.text().await?;
    Ok(parse(&body, domain)?)
}

/// Extract `domain`'s subdomains from a passive DNS response. Unlike the other
/// providers this returns fully-qualified names, which `passive_scan` expects.
fn parse(body: &str, domain: &str) -> Result<Vec<String>, serde_json::Error> {
    let data: Response = serde_json::from_str(body)?;
    let dot_suffix = format!(".{domain}");
    let mut unique_subdomains = HashSet::new();

    for record in data.passive_dns {
        let host = record
            .hostname
            .trim()
            .trim_start_matches("*.")
            .to_lowercase();
        // Keep only real subdomains of the target (skip the apex and
        // unrelated names like "notexample.com" that merely end in it).
        if let Some(stripped) = host.strip_suffix(&dot_suffix)
            && !stripped.is_empty()
            && stripped != "*"
        {
            unique_subdomains.insert(host);
        }
    }

    Ok(unique_subdomains.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::parse;

    fn parsed(hostnames: &[&str]) -> Vec<String> {
        let records: Vec<String> = hostnames
            .iter()
            .map(|h| {
                format!(r#"{{"hostname": "{h}", "address": "93.184.216.34", "record_type": "A"}}"#)
            })
            .collect();
        let body = format!(
            r#"{{"passive_dns": [{}], "count": {}}}"#,
            records.join(","),
            hostnames.len()
        );
        let mut names = parse(&body, "example.com").unwrap();
        names.sort();
        names
    }

    #[test]
    fn keeps_a_real_subdomain_as_a_full_name() {
        assert_eq!(parsed(&["www.example.com"]), ["www.example.com"]);
    }

    #[test]
    fn skips_the_apex() {
        assert!(parsed(&["example.com", ".example.com"]).is_empty());
    }

    #[test]
    fn skips_a_name_that_only_ends_like_the_domain() {
        assert!(parsed(&["notexample.com"]).is_empty());
    }

    #[test]
    fn strips_a_wildcard_label() {
        assert_eq!(
            parsed(&["*.example.com", "*.api.example.com"]),
            ["api.example.com"]
        );
    }

    #[test]
    fn lowercases_an_uppercase_name() {
        assert_eq!(parsed(&["WWW.Example.COM"]), ["www.example.com"]);
    }

    #[test]
    fn rejects_a_body_that_is_not_a_passive_dns_response() {
        assert!(
            parse(
                r#"{"detail": "Anonymous access to this endpoint is limited."}"#,
                "example.com"
            )
            .is_err()
        );
    }
}

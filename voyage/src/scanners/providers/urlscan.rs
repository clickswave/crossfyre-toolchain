use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;

#[derive(Deserialize)]
struct Response {
    results: Vec<SearchResult>,
}

#[derive(Deserialize)]
struct SearchResult {
    page: Option<Page>,
}

#[derive(Deserialize)]
struct Page {
    domain: Option<String>,
}

pub async fn fetch(
    reqwest_client: &Client,
    domain: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let url = format!("https://urlscan.io/api/v1/search/?q=domain:{domain}");
    // Unlike most providers, a non-2xx is an error here so the caller
    // logs it: the keyless API rate-limits hard, and a 429 should show up as a
    // warning rather than as a silent empty result.
    let response = reqwest_client.get(&url).send().await?.error_for_status()?;
    let body = response.text().await?;

    Ok(parse(&body, domain)?)
}

/// Extract the label prefixes of `domain`'s subdomains from a search response.
fn parse(body: &str, domain: &str) -> Result<Vec<String>, serde_json::Error> {
    let data: Response = serde_json::from_str(body)?;
    let dot_suffix = format!(".{domain}");
    let mut unique_subdomains = HashSet::new();

    for host in data
        .results
        .into_iter()
        .filter_map(|r| r.page?.domain)
        .map(|d| d.to_lowercase())
    {
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

    // A real response to `q=domain:githubusercontent.com`, cut down to a few of
    // its entries and to the one field the parser reads. Entries whose page
    // never loaded come back with no `page.domain` at all.
    const SAMPLE: &str = r#"{
        "results": [
            {"page": {"domain": "release-assets.githubusercontent.com"}},
            {"page": {"domain": "release-assets.githubusercontent.com"}},
            {"page": {}},
            {"page": {"domain": "raw.githubusercontent.com"}},
            {"page": {"domain": "gitrank.pages.dev"}},
            {"page": {}},
            {"page": {"domain": "bergamot.ch"}}
        ],
        "total": 10000,
        "took": 31,
        "has_more": true
    }"#;

    #[test]
    fn parse_keeps_unique_subdomain_prefixes_of_a_saved_response() {
        let mut prefixes = parse(SAMPLE, "githubusercontent.com").unwrap();
        prefixes.sort();
        assert_eq!(prefixes, ["raw", "release-assets"]);
    }

    #[test]
    fn parse_lowercases_and_skips_the_apex_look_alikes_and_missing_hosts() {
        let body = r#"{"results": [
            {"page": {"domain": "API.Example.com"}},
            {"page": {"domain": "a.b.example.com"}},
            {"page": {"domain": "example.com"}},
            {"page": {"domain": "notexample.com"}},
            {"page": {"domain": null}},
            {"page": null},
            {"task": {"domain": "www.example.com"}}
        ]}"#;
        let mut prefixes = parse(body, "example.com").unwrap();
        prefixes.sort();
        assert_eq!(prefixes, ["a.b", "api"]);
    }

    #[test]
    fn parse_rejects_a_non_search_body() {
        assert!(parse(r#"{"message": "Rate limit exceeded"}"#, "example.com").is_err());
    }
}

use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;

#[derive(Deserialize)]
struct Response {
    name_value: String,
}

pub async fn fetch(
    reqwest_client: &Client,
    domain: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let url = format!("https://crt.sh/?q={domain}&output=json");
    let response = reqwest_client.get(&url).send().await?;

    if !response.status().is_success() {
        return Ok(vec![]);
    }
    let body = response.text().await?;

    Ok(parse(&body, domain)?)
}

/// Extract the label prefixes of `domain`'s subdomains from a crt.sh JSON
/// response.
fn parse(body: &str, domain: &str) -> Result<Vec<String>, serde_json::Error> {
    let entries: Vec<Response> = serde_json::from_str(body)?;
    let mut unique_subdomains = HashSet::new();
    // crt.sh packs every SAN of a cert into one newline-separated
    // name_value, so split it into individual hostnames before parsing.
    let dot_suffix = format!(".{domain}");
    for entry in entries {
        for raw in entry.name_value.split(['\n', '\r']) {
            let host = raw.trim().trim_start_matches("*.").to_lowercase();
            if host.is_empty() {
                continue;
            }
            // Keep only real subdomains of the target (skip the apex and
            // unrelated names like "notgoogle.com" that merely end in it).
            if let Some(stripped) = host.strip_suffix(&dot_suffix)
                && !stripped.is_empty()
                && stripped != "*"
            {
                unique_subdomains.insert(stripped.to_string());
            }
        }
    }

    Ok(unique_subdomains.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::parse;

    // A real response for `clickswave.org`, cut down to a few of its entries and
    // to the one field the parser reads. The wildcard certificate packs two
    // names into one `name_value`.
    const SAMPLE: &str = r#"[
        {"name_value": "admin.clickswave.org"},
        {"name_value": "status.clickswave.org"},
        {"name_value": "admin.clickswave.org"},
        {"name_value": "*.clickswave.org\nclickswave.org"},
        {"name_value": "assets.clickswave.org"}
    ]"#;

    #[test]
    fn parse_keeps_unique_subdomain_prefixes_of_a_saved_response() {
        let mut prefixes = parse(SAMPLE, "clickswave.org").unwrap();
        prefixes.sort();
        assert_eq!(prefixes, ["admin", "assets", "status"]);
    }

    #[test]
    fn parse_splits_lowercases_and_skips_the_apex_look_alikes_and_wildcards() {
        let body = r#"[
            {"name_value": "api.example.com\nWWW.Example.com\r\n*.mail.example.com"},
            {"name_value": "example.com"},
            {"name_value": "*.example.com"},
            {"name_value": "notexample.com"},
            {"name_value": "  "}
        ]"#;
        let mut prefixes = parse(body, "example.com").unwrap();
        prefixes.sort();
        assert_eq!(prefixes, ["api", "mail", "www"]);
    }

    #[test]
    fn parse_rejects_a_non_crt_sh_body() {
        assert!(parse("<html>502 Bad Gateway</html>", "example.com").is_err());
    }
}

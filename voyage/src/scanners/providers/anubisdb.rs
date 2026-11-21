use std::collections::HashSet;
use transport::Client;

pub async fn fetch(
    reqwest_client: &Client,
    domain: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let url = format!("https://anubisdb.com/anubis/subdomains/{domain}");
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

    // Some entries are several names joined with `<br>`, some carry a trailing
    // dot, and some are wildcards, so each is split and cleaned up first.
    for raw in hosts.iter().flat_map(|h| h.split("<br>")) {
        let host = raw
            .trim()
            .trim_end_matches('.')
            .trim_start_matches("*.")
            .to_lowercase();
        // Keep only real subdomains of the target (skip the apex and
        // unrelated names like "notexample.com" that merely end in it).
        if let Some(stripped) = host.strip_suffix(&dot_suffix)
            && !stripped.is_empty()
            && stripped != "*"
        {
            unique_subdomains.insert(stripped.to_string());
        }
    }

    Ok(unique_subdomains.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::parse;

    // A real response for `jonlu.ca`, cut down to a few of its entries,
    // including a wildcard, a joined entry, a trailing dot and the apex.
    const SAMPLE: &str = r#"[
        "*.jonlu.ca",
        "blog.jonlu.ca",
        "blog.jonlu.ca<br>jonlu.ca<br>secure.jonlu.ca<br>www.jonlu.ca",
        "box.jonlu.ca",
        "churning.us",
        "jonlu.ca",
        "jonlu.ca."
    ]"#;

    #[test]
    fn parse_keeps_unique_subdomain_prefixes_of_a_saved_response() {
        let mut prefixes = parse(SAMPLE, "jonlu.ca").unwrap();
        prefixes.sort();
        assert_eq!(prefixes, ["blog", "box", "secure", "www"]);
    }

    #[test]
    fn parse_lowercases_and_skips_the_apex_look_alikes_and_wildcards() {
        let body = r#"[
            "API.Example.com",
            "a.b.example.com",
            "*.mail.example.com",
            "*.example.com",
            "example.com",
            "notexample.com"
        ]"#;
        let mut prefixes = parse(body, "example.com").unwrap();
        prefixes.sort();
        assert_eq!(prefixes, ["a.b", "api", "mail"]);
    }

    #[test]
    fn parse_returns_nothing_for_an_empty_array() {
        assert!(parse("[]", "example.com").unwrap().is_empty());
    }

    #[test]
    fn parse_rejects_a_non_array_body() {
        assert!(parse("<html>502 Bad Gateway</html>", "example.com").is_err());
    }
}

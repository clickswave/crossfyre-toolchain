use reqwest::Client;
use std::collections::HashSet;

pub async fn fetch(
    reqwest_client: &Client,
    domain: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let url = format!("https://api.hackertarget.com/hostsearch/?q={domain}");
    let response = reqwest_client.get(&url).send().await?;

    if !response.status().is_success() {
        return Ok(vec![]);
    }

    let body = response.text().await?;
    Ok(parse(&body, domain))
}

/// Extract the label prefixes of `domain`'s subdomains from a hostsearch body,
/// which is one `host,ip` pair per line.
fn parse(body: &str, domain: &str) -> Vec<String> {
    let dot_suffix = format!(".{domain}");
    let mut unique_subdomains = HashSet::new();

    for line in body.lines() {
        let Some((raw, _ip)) = line.split_once(',') else {
            continue;
        };
        let host = raw.trim().trim_start_matches("*.").to_lowercase();
        // Keep only real subdomains of the target (skip the apex and
        // unrelated names like "notexample.com" that merely end in it).
        if let Some(stripped) = host.strip_suffix(&dot_suffix)
            && !stripped.is_empty()
            && stripped != "*"
        {
            unique_subdomains.insert(stripped.to_string());
        }
    }

    unique_subdomains.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::parse;

    fn parsed(body: &str) -> Vec<String> {
        let mut prefixes = parse(body, "example.com");
        prefixes.sort();
        prefixes
    }

    #[test]
    fn keeps_a_real_subdomain() {
        assert_eq!(parsed("www.example.com,93.184.216.34"), ["www"]);
    }

    #[test]
    fn skips_the_apex() {
        assert!(parsed("example.com,93.184.216.34\n.example.com,93.184.216.34").is_empty());
    }

    #[test]
    fn skips_a_name_that_only_ends_like_the_domain() {
        assert!(parsed("notexample.com,93.184.216.35").is_empty());
    }

    #[test]
    fn strips_a_wildcard_label() {
        assert_eq!(
            parsed("*.example.com,93.184.216.34\n*.api.example.com,93.184.216.36"),
            ["api"]
        );
    }

    #[test]
    fn lowercases_an_uppercase_name() {
        assert_eq!(parsed("WWW.Example.COM,93.184.216.34"), ["www"]);
    }

    #[test]
    fn ignores_lines_that_are_not_host_ip_pairs() {
        assert!(parsed("API count exceeded - Increase Quota with Membership").is_empty());
    }
}

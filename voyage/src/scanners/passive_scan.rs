use std::collections::HashMap;

/// Query every passive source and union the results.
///
/// The sources run CONCURRENTLY. They used to run one after another, which made
/// a single slow provider the floor for the whole passive phase: crt.sh alone is
/// regularly the full 15s timeout, so a four-source enum could spend a minute
/// waiting on providers that answer in under a second each. Wall-clock is now
/// the slowest single source rather than their sum, which is what makes a
/// passive enum viable behind an interactive request.
///
/// Every source is best-effort. One failing or timing out costs its results and
/// nothing else, so the merge below runs over whatever came back.
pub async fn execute(
    domain: &str,
    user_agent: &str,
    exclude_sources: &[String],
) -> Result<HashMap<String, String>, Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .user_agent(user_agent)
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    let skipped = |name: &str| exclude_sources.iter().any(|s| s == name);

    // Each arm resolves to the source's names, or an empty vec if it was
    // excluded or errored. `join!` polls them on one task, so this needs no
    // spawning and no 'static bounds on the borrowed client.
    let (crtsh, certspotter, hackertarget, alienvault) = tokio::join!(
        async {
            if skipped("crt.sh") {
                return vec![];
            }
            match crate::scanners::providers::crt_sh::fetch(&client, domain).await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("[WARN] crt.sh error: {e}");
                    vec![]
                }
            }
        },
        async {
            if skipped("certspotter") {
                return vec![];
            }
            match crate::scanners::providers::certspotter::fetch(&client, domain).await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("[WARN] certspotter error: {e}");
                    vec![]
                }
            }
        },
        async {
            if skipped("hackertarget") {
                return vec![];
            }
            match crate::scanners::providers::hackertarget::fetch(&client, domain).await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("[WARN] hackertarget error: {e}");
                    vec![]
                }
            }
        },
        async {
            if skipped("alienvault") {
                return vec![];
            }
            match crate::scanners::providers::alienvault::fetch(&client, domain).await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("[WARN] alienvault error: {e}");
                    vec![]
                }
            }
        },
    );

    // Merged in a fixed order so the recorded `source` for a name found by more
    // than one provider is deterministic (last writer wins), regardless of which
    // request happened to finish first.
    let mut results: HashMap<String, String> = HashMap::new();
    for (prefix, source) in crtsh
        .into_iter()
        .map(|p| (p, "crt.sh"))
        .chain(certspotter.into_iter().map(|p| (p, "certspotter")))
        .chain(hackertarget.into_iter().map(|p| (p, "hackertarget")))
    {
        // These three return the label prefix; reconstruct the full name.
        results.insert(format!("{prefix}.{domain}"), source.to_string());
    }
    // alienvault returns fully-qualified names already.
    for subdomain in alienvault {
        results.insert(subdomain, "alienvault".to_string());
    }

    Ok(results)
}

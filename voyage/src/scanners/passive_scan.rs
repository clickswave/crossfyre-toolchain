use std::collections::HashMap;

/// The names `--exclude-passive-source` takes. They live next to the scan that
/// reads them, so a source added below and the list the CLI validates against
/// cannot drift apart: the same constant is the provider's exclusion check and
/// its entry in `SOURCES`.
pub const CRT_SH: &str = "crt.sh";
pub const CERTSPOTTER: &str = "certspotter";
pub const HACKERTARGET: &str = "hackertarget";
pub const ALIENVAULT: &str = "alienvault";
pub const URLSCAN: &str = "urlscan";
pub const SUBDOMAIN_CENTER: &str = "subdomain.center";

/// Every passive source, in the order `execute` runs them.
pub const SOURCES: [&str; 6] = [
    CRT_SH,
    CERTSPOTTER,
    HACKERTARGET,
    ALIENVAULT,
    URLSCAN,
    SUBDOMAIN_CENTER,
];

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
///
/// The sources are third parties, not the target, but they are asked about the
/// target, so the questions go out the way the rest of the op's traffic does.
pub async fn execute(
    domain: &str,
    user_agent: &str,
    exclude_sources: &[String],
    egress: &transport::Egress,
) -> Result<HashMap<String, String>, Box<dyn std::error::Error + Send + Sync>> {
    // A plain client that says who it is: no browser emulation for a provider's API.
    let client = transport::build_client(
        transport::ClientConfig {
            timeout: Some(std::time::Duration::from_secs(15)),
            redirect: transport::Redirect::Limited(10),
            user_agent: Some(user_agent.to_string()),
            emulate: false,
            ..Default::default()
        },
        egress,
    )?;

    let skipped = |name: &str| exclude_sources.iter().any(|s| s == name);

    // Each arm resolves to the source's names, or an empty vec if it was
    // excluded or errored. `join!` polls them on one task, so this needs no
    // spawning and no 'static bounds on the borrowed client.
    let (crtsh, certspotter, hackertarget, alienvault, urlscan, subdomain_center) = tokio::join!(
        async {
            if skipped(CRT_SH) {
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
            if skipped(CERTSPOTTER) {
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
            if skipped(HACKERTARGET) {
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
            if skipped(ALIENVAULT) {
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
        async {
            if skipped(URLSCAN) {
                return vec![];
            }
            match crate::scanners::providers::urlscan::fetch(&client, domain).await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("[WARN] urlscan error: {e}");
                    vec![]
                }
            }
        },
        async {
            if skipped(SUBDOMAIN_CENTER) {
                return vec![];
            }
            match crate::scanners::providers::subdomain_center::fetch(&client, domain).await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("[WARN] subdomain.center error: {e}");
                    vec![]
                }
            }
        },
    );

    // Merged in a fixed order so the recorded `source` for a name found by more
    // than one provider is deterministic (last writer wins), regardless of which
    // request happened to finish first. subdomain.center aggregates the others,
    // so it goes first and a name keeps the source that found it originally.
    let mut results: HashMap<String, String> = HashMap::new();
    for (prefix, source) in subdomain_center
        .into_iter()
        .map(|p| (p, SUBDOMAIN_CENTER))
        .chain(crtsh.into_iter().map(|p| (p, CRT_SH)))
        .chain(certspotter.into_iter().map(|p| (p, CERTSPOTTER)))
        .chain(hackertarget.into_iter().map(|p| (p, HACKERTARGET)))
        .chain(urlscan.into_iter().map(|p| (p, URLSCAN)))
    {
        // These return the label prefix; reconstruct the full name.
        results.insert(format!("{prefix}.{domain}"), source.to_string());
    }
    // alienvault returns fully-qualified names already.
    for subdomain in alienvault {
        results.insert(subdomain, ALIENVAULT.to_string());
    }

    Ok(results)
}

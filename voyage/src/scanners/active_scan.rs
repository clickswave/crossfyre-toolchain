use crate::scanners::techniques;
use hickory_resolver::TokioResolver;
use transport::Client;

/// The names `--exclude-active-technique` takes. They live next to the scan that
/// reads them, so a technique added below and the list the CLI validates against
/// cannot drift apart: the same constant is the technique's exclusion check and
/// its entry in `TECHNIQUES`.
pub const IPV4_LOOKUP: &str = "ipv4_lookup";
pub const IPV6_LOOKUP: &str = "ipv6_lookup";
pub const HTTP_PROBING: &str = "http_probing";
pub const HTTPS_PROBING: &str = "https_probing";

/// Every active technique, in the order `execute` tries them.
pub const TECHNIQUES: [&str; 4] = [IPV4_LOOKUP, IPV6_LOOKUP, HTTP_PROBING, HTTPS_PROBING];

pub struct NegativeResult {
    pub level: String,
    pub description: String,
}

pub struct ActiveScanResult {
    pub found: bool,
    pub source: String,
    pub negatives: Vec<NegativeResult>,
}

/// Whether the operator asked for `technique` to be skipped.
fn excluded(exclude_techniques: &[String], technique: &str) -> bool {
    exclude_techniques.iter().any(|t| t == technique)
}

pub async fn execute(
    resolver: &TokioResolver,
    reqwest_client: &Client,
    exclude_techniques: &[String],
    http_probing_ports: &[u16],
    https_probing_ports: &[u16],
    full_subdomain: &str,
) -> ActiveScanResult {
    let domain = full_subdomain.to_string();
    let mut scan_result = ActiveScanResult {
        found: false,
        source: String::new(),
        negatives: vec![],
    };

    // ipv4 lookup
    if !excluded(exclude_techniques, IPV4_LOOKUP) {
        let ipv4_lookup = techniques::ipv4_lookup::execute(resolver, &domain).await;
        match ipv4_lookup {
            Ok(_) => {
                scan_result.found = true;
                scan_result.source = IPV4_LOOKUP.to_string();
                return scan_result;
            }
            Err(e) => scan_result.negatives.push(e),
        }
    }

    // ipv6 lookup
    if !excluded(exclude_techniques, IPV6_LOOKUP) {
        let ipv6_lookup = techniques::ipv6_lookup::execute(resolver, &domain).await;
        match ipv6_lookup {
            Ok(_) => {
                scan_result.found = true;
                scan_result.source = IPV6_LOOKUP.to_string();
                return scan_result;
            }
            Err(e) => scan_result.negatives.push(e),
        }
    }

    // http probing
    if !excluded(exclude_techniques, HTTP_PROBING) {
        let http_probing =
            techniques::http_probing::execute(reqwest_client, &domain, http_probing_ports).await;
        match http_probing {
            Ok(_) => {
                scan_result.found = true;
                scan_result.source = HTTP_PROBING.to_string();
                return scan_result;
            }
            Err(e) => scan_result.negatives.extend(e),
        }
    }

    // https probing
    if !excluded(exclude_techniques, HTTPS_PROBING) {
        let https_probing =
            techniques::https_probing::execute(reqwest_client, &domain, https_probing_ports).await;
        match https_probing {
            Ok(_) => {
                scan_result.found = true;
                scan_result.source = HTTPS_PROBING.to_string();
                return scan_result;
            }
            Err(e) => scan_result.negatives.extend(e),
        }
    }

    scan_result
}

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

/// The ports of `ports` the scope lets a probe of `name` go to, with a line for each one
/// it does not, or every port when there is no scope.
fn admitted(
    scope: Option<&cfx_scope::Scope>,
    name: &str,
    ports: &[u16],
    negatives: &mut Vec<NegativeResult>,
) -> Vec<u16> {
    let Some(scope) = scope else {
        return ports.to_vec();
    };
    ports
        .iter()
        .copied()
        .filter(|port| {
            let ok = scope.admits(name, Some(*port));
            if !ok {
                negatives.push(NegativeResult {
                    level: "debug".to_string(),
                    description: format!("{name}:{port} not probed: outside the scope given"),
                });
            }
            ok
        })
        .collect()
}

/// Try `full_subdomain` with each technique `config` does not exclude, in order, until
/// one finds it. A probe goes only to a name and port the scope admits.
pub async fn execute(
    resolver: &TokioResolver,
    reqwest_client: &Client,
    config: &crate::scanner::EnumConfig,
    full_subdomain: &str,
) -> ActiveScanResult {
    let exclude_techniques = &config.exclude_active_techniques;
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
    let http_probing_ports = admitted(
        config.scope.as_ref(),
        &domain,
        &config.http_probing_ports,
        &mut scan_result.negatives,
    );
    if !excluded(exclude_techniques, HTTP_PROBING) && !http_probing_ports.is_empty() {
        let http_probing =
            techniques::http_probing::execute(reqwest_client, &domain, &http_probing_ports).await;
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
    let https_probing_ports = admitted(
        config.scope.as_ref(),
        &domain,
        &config.https_probing_ports,
        &mut scan_result.negatives,
    );
    if !excluded(exclude_techniques, HTTPS_PROBING) && !https_probing_ports.is_empty() {
        let https_probing =
            techniques::https_probing::execute(reqwest_client, &domain, &https_probing_ports).await;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::EnumConfig;
    use cfx_tunnel::recorder::Fixture;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn config(port: u16, scope: Option<&[&str]>, follow_redirects: bool) -> EnumConfig {
        EnumConfig {
            scan_id: "s".into(),
            tasks: 1,
            interval_ms: 0,
            // The lookups go to resolvers, which a test does not reach.
            exclude_active_techniques: vec![IPV4_LOOKUP.into(), IPV6_LOOKUP.into()],
            http_probing_ports: vec![port],
            https_probing_ports: vec![],
            active_user_agent: "voyage-test".into(),
            active_random_user_agent: false,
            dns_server: String::new(),
            adaptive_rate: false,
            adaptive_resilience: false,
            posture: "balanced".into(),
            evasive: false,
            identify: None,
            block_internal: false,
            scope: scope
                .map(|s| cfx_scope::parse(&s.iter().map(|e| e.to_string()).collect::<Vec<_>>()).0),
            follow_redirects,
            egress: transport::Egress::Direct,
        }
    }

    async fn probed(config: &EnumConfig, name: &str) -> ActiveScanResult {
        let resolver = crate::libs::dns::create_resolver(Some("127.0.0.1:9")).unwrap();
        let client = crate::scanner::probe_client(config, "voyage-test").unwrap();
        execute(&resolver, &client, config, name).await
    }

    /// A name the scope does not admit is not probed, and one it admits is.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_probe_goes_only_to_a_name_and_port_in_the_scope() {
        let fx = Fixture::http("text/html", "ok".into()).await;
        let outside = probed(&config(fx.port, Some(&["other.test"]), true), "localhost").await;
        assert!(!outside.found);
        assert!(outside.negatives.iter().any(|n| {
            n.description
                .contains("not probed: outside the scope given")
        }));
        let other_port = probed(&config(fx.port, Some(&["localhost:1"]), true), "localhost").await;
        assert!(!other_port.found);
        assert_eq!(fx.connections(), 0, "a name outside the scope was probed");

        let inside = probed(&config(fx.port, Some(&["localhost"]), true), "localhost").await;
        assert!(inside.found);
        let unfenced = probed(&config(fx.port, None, true), "localhost").await;
        assert!(unfenced.found);
        assert_eq!(fx.connections(), 2);
    }

    /// A probe told not to follow redirects follows none, and one left to follows it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_probe_follows_no_redirect_when_told_not_to() {
        let landing = Fixture::http("text/html", "ok".into()).await;
        let to = format!("http://localhost:{}/", landing.port);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let to = to.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = s.read(&mut buf).await;
                    let reply = format!(
                        "HTTP/1.1 302 Found\r\nLocation: {to}\r\nContent-Length: 0\r\n\r\n"
                    );
                    let _ = s.write_all(reply.as_bytes()).await;
                });
            }
        });
        assert!(probed(&config(port, None, false), "localhost").await.found);
        assert_eq!(landing.connections(), 0, "a redirect was followed");
        assert!(probed(&config(port, None, true), "localhost").await.found);
        assert_eq!(landing.connections(), 1);
    }
}

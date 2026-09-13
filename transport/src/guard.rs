//! Connect-time destination guard: refuse to hand the connector a private address.
//!
//! ## Why this lives at the resolver, not at the caller
//!
//! The obvious place to check a destination is where the target is accepted, and
//! for a control plane that is right. It is not sufficient for an engine, for two
//! reasons that a pre-check structurally cannot cover:
//!
//!   * **Redirects.** A public host the caller was allowed to reach can answer
//!     `302 http://10.0.0.5:8080/`. The pre-check saw the first hostname and
//!     nothing else. Following that redirect reaches an arbitrary internal host
//!     AND port, once per request.
//!   * **Rebinding.** A pre-check resolves once; the connector resolves again.
//!     A name whose record flips between the two passes the check and connects
//!     somewhere else.
//!
//! A resolver hook has neither gap, because it is the thing the connector asks
//! for an address, on every connection, including every redirect hop. Whatever
//! it does not return cannot be dialled.
//!
//! ## Why filtering rather than rejecting
//!
//! A name that resolves to both a public and a private address is not
//! necessarily hostile: split-horizon DNS and dual-homed hosts do this. Handing
//! back only the public addresses is both more permissive for those and STRICTER
//! against an attacker, because the connector never receives an internal address
//! to try. Rejecting the whole name would be the weaker choice dressed up as the
//! stricter one.
//!
//! ## Scope
//!
//! Off by default. Engines are supposed to reach arbitrary customer targets, and
//! a customer scanning their own RFC1918 network from a node inside it is the
//! product working. This is for the paths where the caller is anonymous and the
//! egress is shared: the free public tools. `ClientConfig::block_internal` turns
//! it on, and nothing else should.

use std::net::{IpAddr, SocketAddr};

/// Addresses an untrusted caller must never be able to reach through us.
///
/// Deliberately the same classification as the control plane's own guard
/// (`api_switch/src/libs/ssrf.rs`). Two copies is not ideal, but they sit in
/// different repositories with different release cadences, and a shared crate
/// for eleven lines of range checks would couple the open toolchain to the
/// closed control plane. If you change one, change the other.
pub fn is_internal(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local() // 169.254.0.0/16, incl. the cloud metadata address
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.octets()[0] == 0
                // 100.64.0.0/10 carrier-grade NAT
                || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]))
                // 198.18.0.0/15 benchmarking
                || (v4.octets()[0] == 198 && (18..20).contains(&v4.octets()[1]))
                // 240.0.0.0/4 reserved
                || v4.octets()[0] >= 240
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // fc00::/7 unique-local
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // fe80::/10 link-local
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                // IPv4-mapped, re-checked as v4 so ::ffff:127.0.0.1 is caught
                || v6
                    .to_ipv4_mapped()
                    .map(|m| is_internal(&IpAddr::V4(m)))
                    .unwrap_or(false)
        }
    }
}

/// Resolve `host` and keep only the addresses that are safe to dial.
///
/// Shared by both backend impls below so the filtering logic exists once.
async fn resolve_public(host: String) -> Result<Vec<SocketAddr>, String> {
    // Port 0: the caller (hyper) overrides it with the real port afterwards.
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
        .await
        .map_err(|e| format!("could not resolve {host}: {e}"))?
        .collect();

    let public: Vec<SocketAddr> = addrs
        .iter()
        .copied()
        .filter(|a| !is_internal(&a.ip()))
        .collect();

    if public.is_empty() {
        // Generic on purpose. The precise reason is a useful oracle for mapping
        // an internal network, which is the thing being prevented.
        return Err("destination is not a permitted address".to_string());
    }
    Ok(public)
}

/// A DNS resolver that only ever returns publicly routable addresses.
///
/// Implements the resolver trait of whichever backend(s) are compiled, so one
/// value can be installed on a `reqwest` or a `wreq` client.
#[derive(Debug, Clone, Copy, Default)]
pub struct PublicOnlyResolver;

impl reqwest::dns::Resolve for PublicOnlyResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs = resolve_public(host).await?;
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

#[cfg(feature = "impersonate")]
impl wreq::dns::Resolve for PublicOnlyResolver {
    fn resolve(&self, name: wreq::dns::Name) -> wreq::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs = resolve_public(host).await?;
            Ok(Box::new(addrs.into_iter()) as wreq::dns::Addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn blocks_the_ranges_that_matter() {
        for s in [
            "127.0.0.1",
            "10.0.0.5",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.1",
            // The one an SSRF is usually aiming for.
            "169.254.169.254",
            "0.0.0.0",
            "100.64.0.1", // CGNAT
            "198.18.0.1", // benchmarking
            "240.0.0.1",  // reserved
            "255.255.255.255",
        ] {
            assert!(is_internal(&v4(s)), "{s} should be blocked");
        }
    }

    #[test]
    fn allows_ordinary_public_addresses() {
        for s in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "172.32.0.1",
            "100.128.0.1",
        ] {
            assert!(!is_internal(&v4(s)), "{s} should be allowed");
        }
    }

    #[test]
    fn ipv6_mapped_v4_is_not_a_bypass() {
        // ::ffff:127.0.0.1 is the classic way past a v4-only check.
        assert!(is_internal(&"::ffff:127.0.0.1".parse().unwrap()));
        assert!(is_internal(&"::ffff:10.0.0.1".parse().unwrap()));
        assert!(is_internal(&"::1".parse().unwrap()));
        assert!(is_internal(&"fc00::1".parse().unwrap()));
        assert!(is_internal(&"fe80::1".parse().unwrap()));
        assert!(!is_internal(&"2606:4700:4700::1111".parse().unwrap()));
    }

    #[tokio::test]
    async fn a_name_resolving_only_inward_is_refused() {
        // localhost resolves to 127.0.0.1 and/or ::1, all of which are filtered,
        // leaving nothing to dial.
        assert!(resolve_public("localhost".to_string()).await.is_err());
    }

    #[tokio::test]
    async fn the_error_does_not_name_the_address() {
        // The message must not become an oracle for what is on the inside.
        if let Err(e) = resolve_public("localhost".to_string()).await {
            assert!(!e.contains("127.0.0.1"), "error leaked the address: {e}");
            assert!(!e.contains("::1"), "error leaked the address: {e}");
        }
    }
}

#[cfg(test)]
mod client_tests {
    use crate::{build_client, ClientConfig, Redirect};

    /// End-to-end through a real built client: the guard must stop the request
    /// at resolution, not merely exist as a filter function.
    ///
    /// Uses `localhost` because it resolves offline and only ever to loopback,
    /// so this asserts real behaviour without needing the network.
    #[tokio::test]
    async fn a_guarded_client_cannot_reach_loopback() {
        let client = build_client(ClientConfig {
            block_internal: true,
            redirect: Redirect::None,
            timeout: Some(std::time::Duration::from_secs(5)),
            ..Default::default()
        })
        .expect("client builds");

        let err = client
            .get("http://localhost/")
            .send()
            .await
            .expect_err("request to loopback must fail");
        let msg = err.to_string().to_lowercase();
        // Whatever the backend wraps it in, it must not have connected.
        assert!(
            !msg.contains("404") && !msg.contains("status"),
            "looks like it actually connected: {msg}"
        );
    }

    /// The same client with the guard off is unchanged, so enabling the flag is
    /// what changes behaviour and nothing else does.
    #[tokio::test]
    async fn an_unguarded_client_still_resolves_loopback() {
        let client = build_client(ClientConfig {
            block_internal: false,
            redirect: Redirect::None,
            timeout: Some(std::time::Duration::from_millis(1500)),
            ..Default::default()
        })
        .expect("client builds");

        // Nothing is listening, so this fails to CONNECT rather than failing to
        // RESOLVE. Either way it errors; what matters is that the failure is not
        // the guard's, which is why the message is checked.
        if let Err(e) = client.get("http://localhost:1/").send().await {
            assert!(
                !e.to_string().contains("not a permitted address"),
                "guard fired while disabled: {e}"
            );
        }
    }
}

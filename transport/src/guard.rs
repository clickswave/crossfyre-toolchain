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
//! The connector does not ask it about a host that is already an address, so a
//! redirect to `http://10.0.0.5/` is refused by the client's redirect policy
//! instead, with [`is_internal_literal`].
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
//! it on for a client and `dial`'s `block_internal` for a raw connection, and
//! nothing else should.
//!
//! A client that sends through a proxy never asks this resolver about a
//! destination, since the proxy looks names up. Such a client cannot have the
//! filter; see [`crate::egress`] for which combinations are refused.

use std::io;
use std::net::{IpAddr, SocketAddr};

/// The one refusal message. Generic on purpose: the precise reason is a useful
/// oracle for mapping an internal network, which is the thing being prevented.
pub(crate) const NOT_PERMITTED: &str = "destination is not a permitted address";

/// Addresses an untrusted caller must never be able to reach through us. It lives in
/// `cfx_tunnel` because the node's gateway applies the same ranges and does not link
/// this crate.
pub use cfx_tunnel::is_internal;

/// Is `host`, as a URL spells it, an internal address? A name is not: names are
/// filtered when they are resolved. IPv6 may come with or without its brackets.
pub fn is_internal_literal(host: &str) -> bool {
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    bare.parse::<IpAddr>().is_ok_and(|ip| is_internal(&ip))
}

/// Resolve `host` and keep only the addresses that are safe to dial.
///
/// Shared by both backend impls below and by [`crate::dial`], so the filtering
/// logic exists once. The addresses come back on port 0, for the caller to set.
pub(crate) async fn resolve_public(host: &str) -> io::Result<Vec<SocketAddr>> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, 0))
        .await
        .map_err(|e| io::Error::new(e.kind(), format!("could not resolve {host}: {e}")))?
        .collect();

    let public: Vec<SocketAddr> = addrs
        .iter()
        .copied()
        .filter(|a| !is_internal(&a.ip()))
        .collect();

    if public.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            NOT_PERMITTED,
        ));
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
            let addrs = resolve_public(&host).await?;
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

#[cfg(feature = "impersonate")]
impl wreq::dns::Resolve for PublicOnlyResolver {
    fn resolve(&self, name: wreq::dns::Name) -> wreq::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs = resolve_public(&host).await?;
            Ok(Box::new(addrs.into_iter()) as wreq::dns::Addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_name_resolving_only_inward_is_refused() {
        // localhost resolves to 127.0.0.1 and/or ::1, all of which are filtered,
        // leaving nothing to dial.
        assert!(resolve_public("localhost").await.is_err());
    }

    #[tokio::test]
    async fn the_error_does_not_name_the_address() {
        // The message must not become an oracle for what is on the inside.
        if let Err(e) = resolve_public("localhost").await {
            let e = e.to_string();
            assert!(!e.contains("127.0.0.1"), "error leaked the address: {e}");
            assert!(!e.contains("::1"), "error leaked the address: {e}");
        }
    }
}

#[cfg(test)]
mod client_tests {
    use crate::{ClientConfig, Egress, Redirect, build_client};

    /// End-to-end through a real built client: the guard must stop the request
    /// at resolution, not merely exist as a filter function.
    ///
    /// Uses `localhost` because it resolves offline and only ever to loopback,
    /// so this asserts real behaviour without needing the network.
    #[tokio::test]
    async fn a_guarded_client_cannot_reach_loopback() {
        let client = build_client(
            ClientConfig {
                block_internal: true,
                redirect: Redirect::None,
                timeout: Some(std::time::Duration::from_secs(5)),
                ..Default::default()
            },
            &Egress::Direct,
        )
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
        let client = build_client(
            ClientConfig {
                block_internal: false,
                redirect: Redirect::None,
                timeout: Some(std::time::Duration::from_millis(1500)),
                ..Default::default()
            },
            &Egress::Direct,
        )
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

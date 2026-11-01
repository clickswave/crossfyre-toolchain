//! `transport::dial`, the one way an engine opens a raw connection: through a
//! proxy, to a pinned address, or direct with private addresses refused.
//!
//! Only [`Egress::Direct`] and [`Egress::Proxy`] are used here, which never read the
//! environment, so these tests can run side by side. `Egress::Inherit` is covered
//! in `egress_env.rs`, which sets `CROSSFYRE_EGRESS_PROXY` for its process.

mod common;

use std::io::ErrorKind;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use common::{
    Answer, BODY, NAME, basic, closed_port, destination, fetch_over, http, socks4, socks5,
};
use transport::{Egress, TunnelError, dial};

const QUICK: Duration = Duration::from_secs(3);

fn proxy(url: String) -> Egress {
    Egress::Proxy(url)
}

/// The proxy's failure carried inside a dial error.
fn tunnel_error(e: &std::io::Error) -> Option<&TunnelError> {
    e.get_ref()?.downcast_ref::<TunnelError>()
}

#[tokio::test]
async fn socks5_with_credentials_carries_the_name() {
    let p = socks5(Some(("op", "0123abcd"))).await;
    let mut t = dial(
        &proxy(format!("socks5h://op:0123abcd@127.0.0.1:{}", p.port)),
        NAME,
        443,
        false,
        QUICK,
        None,
    )
    .await
    .expect("dialled through the proxy");
    assert!(fetch_over(&mut t).await.ends_with(BODY));
    let seen = p.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        (seen[0].host.as_str(), seen[0].port, seen[0].name),
        (NAME, 443, true)
    );
    assert_eq!(seen[0].user.as_deref(), Some("op"));
    assert_eq!(seen[0].pass.as_deref(), Some("0123abcd"));
    assert_eq!(seen[0].request, "GET /over HTTP/1.1");
}

#[tokio::test]
async fn socks4a_carries_the_name() {
    let p = socks4().await;
    let mut t = dial(
        &proxy(format!("socks4://scanner@127.0.0.1:{}", p.port)),
        NAME,
        80,
        false,
        QUICK,
        None,
    )
    .await
    .expect("dialled through the proxy");
    assert!(fetch_over(&mut t).await.ends_with(BODY));
    let seen = p.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        (seen[0].host.as_str(), seen[0].port, seen[0].name),
        (NAME, 80, true)
    );
    assert_eq!(seen[0].user.as_deref(), Some("scanner"));
}

#[tokio::test]
async fn http_connect_carries_the_name_and_the_credentials() {
    let p = http(Answer::Open).await;
    let mut t = dial(
        &proxy(format!("http://user:secret@127.0.0.1:{}", p.port)),
        NAME,
        8443,
        false,
        QUICK,
        None,
    )
    .await
    .expect("dialled through the proxy");
    assert!(fetch_over(&mut t).await.ends_with(BODY));
    let seen = p.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].how, "connect");
    assert_eq!((seen[0].host.as_str(), seen[0].port), (NAME, 8443));
    assert_eq!(
        seen[0].proxy_authorization.as_deref(),
        Some(basic("user", "secret").as_str())
    );
}

#[tokio::test]
async fn a_407_is_an_auth_error() {
    let p = http(Answer::WantsCredentials).await;
    let e = dial(
        &proxy(format!("http://127.0.0.1:{}", p.port)),
        NAME,
        443,
        false,
        QUICK,
        None,
    )
    .await
    .err()
    .expect("refused");
    assert_eq!(e.kind(), ErrorKind::PermissionDenied, "{e}");
    assert_eq!(tunnel_error(&e), Some(&TunnelError::Auth), "{e}");
}

#[tokio::test]
async fn a_connect_answer_over_8_kib_is_refused() {
    let p = http(Answer::Oversize).await;
    let e = dial(
        &proxy(format!("http://127.0.0.1:{}", p.port)),
        NAME,
        443,
        false,
        QUICK,
        None,
    )
    .await
    .err()
    .expect("refused");
    assert!(
        matches!(tunnel_error(&e), Some(TunnelError::Protocol(_))),
        "{e}"
    );
}

#[tokio::test]
async fn a_proxy_that_never_answers_runs_out_the_timeout() {
    let p = http(Answer::Silent).await;
    let started = Instant::now();
    let e = dial(
        &proxy(format!("http://127.0.0.1:{}", p.port)),
        NAME,
        443,
        false,
        Duration::from_millis(500),
        None,
    )
    .await
    .err()
    .expect("timed out");
    assert_eq!(e.kind(), ErrorKind::TimedOut, "{e}");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn a_dead_proxy_is_an_error_and_nothing_goes_direct() {
    let dest = destination().await;
    for scheme in ["socks5h", "socks4a", "http"] {
        let r = dial(
            &proxy(format!("{scheme}://127.0.0.1:{}", closed_port())),
            "127.0.0.1",
            dest.port,
            false,
            QUICK,
            None,
        )
        .await;
        assert!(r.is_err(), "{scheme}: connected with the proxy down");
    }
    assert_eq!(dest.connections(), 0, "a dial went direct");
}

#[tokio::test]
async fn a_pin_through_a_proxy_is_refused_before_anything_is_dialled() {
    let p = socks5(None).await;
    let dest = destination().await;
    let e = dial(
        &proxy(format!("socks5h://127.0.0.1:{}", p.port)),
        NAME,
        dest.port,
        false,
        QUICK,
        Some(dest.addr()),
    )
    .await
    .err()
    .expect("refused");
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e}");
    assert!(e.to_string().contains("pinned"), "{e}");
    assert_eq!(p.connections(), 0, "the proxy was dialled");
    assert_eq!(dest.connections(), 0, "the pin was dialled");
}

#[tokio::test]
async fn direct_dials_the_pin_and_keeps_the_name() {
    // The name does not resolve, so only the pin can have been dialled.
    let dest = destination().await;
    let mut t = dial(
        &Egress::Direct,
        NAME,
        dest.port,
        false,
        QUICK,
        Some(dest.addr()),
    )
    .await
    .expect("dialled the pin");
    assert!(fetch_over(&mut t).await.ends_with(BODY));
    assert_eq!(dest.connections(), 1);
}

#[tokio::test]
async fn a_pin_on_another_port_is_refused() {
    let dest = destination().await;
    let e = dial(
        &Egress::Direct,
        NAME,
        dest.port.wrapping_add(1).max(1),
        false,
        QUICK,
        Some(dest.addr()),
    )
    .await
    .err()
    .expect("refused");
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e}");
    assert_eq!(dest.connections(), 0);
}

#[tokio::test]
async fn direct_reaches_loopback_when_private_addresses_are_allowed() {
    let dest = destination().await;
    for host in ["127.0.0.1", "localhost"] {
        let mut t = dial(&Egress::Direct, host, dest.port, false, QUICK, None)
            .await
            .unwrap_or_else(|e| panic!("{host}: {e}"));
        assert!(fetch_over(&mut t).await.ends_with(BODY));
    }
    assert_eq!(dest.connections(), 2);
}

#[tokio::test]
async fn private_destinations_are_refused_before_anything_is_dialled() {
    let dest = destination().await;
    let p = socks5(None).await;
    let loopback = dest.addr();
    let cases: Vec<(Egress, &str, Option<SocketAddr>)> = vec![
        (Egress::Direct, "127.0.0.1", None),
        (Egress::Direct, "localhost", None),
        (Egress::Direct, "[::1]", None),
        // The pin is what would be dialled, so the pin is what is checked.
        (Egress::Direct, "example.com", Some(loopback)),
        // Through a proxy a name is the proxy's to vet, but an address is checked here.
        (
            proxy(format!("socks5h://127.0.0.1:{}", p.port)),
            "127.0.0.1",
            None,
        ),
        (
            proxy(format!("socks5h://127.0.0.1:{}", p.port)),
            "169.254.169.254",
            None,
        ),
    ];
    for (egress, host, pin) in cases {
        let e = dial(&egress, host, dest.port, true, QUICK, pin)
            .await
            .err()
            .unwrap_or_else(|| panic!("{egress:?} {host} {pin:?}: connected"));
        assert_eq!(e.kind(), ErrorKind::PermissionDenied, "{host}: {e}");
        // The refusal does not say what the name resolved to.
        assert!(!e.to_string().contains("127.0.0.1"), "{host}: {e}");
    }
    assert_eq!(dest.connections(), 0, "a private destination was dialled");
    assert_eq!(p.connections(), 0, "the proxy was dialled");
}

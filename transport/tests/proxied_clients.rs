//! HTTP clients built for [`Egress::Proxy`] send through the proxy they are given,
//! on whichever backend this build compiles: rustls reqwest by default, and the
//! BoringSSL backend the engines ship with under `--features impersonate`, which
//! CI also runs these under.
//!
//! [`Egress::Proxy`] never reads the environment, so these tests can run side by
//! side.

mod common;

use std::time::Duration;

use common::{Answer, BODY, NAME, Recorder, basic, closed_port, destination, http, socks4, socks5};
use transport::{BuildError, ClientConfig, Egress, Redirect, build_client};

fn client(egress: &Egress, cfg: ClientConfig) -> Result<transport::Client, BuildError> {
    build_client(
        ClientConfig {
            timeout: Some(Duration::from_secs(5)),
            redirect: Redirect::None,
            ..cfg
        },
        egress,
    )
}

async fn get(c: &transport::Client, url: &str) -> Result<(u16, String), String> {
    let r = c.get(url).send().await.map_err(|e| e.to_string())?;
    let status = r.status().as_u16();
    let body = r.text().await.map_err(|e| e.to_string())?;
    Ok((status, body))
}

fn proxy(url: String) -> Egress {
    Egress::Proxy(url)
}

/// The one request `p` carried, after checking there was exactly one.
fn only(p: &Recorder) -> common::Seen {
    let seen = p.seen();
    assert_eq!(seen.len(), 1, "requests through the proxy: {seen:?}");
    seen.into_iter().next().unwrap()
}

#[tokio::test]
async fn socks5_carries_the_request_and_the_name_goes_unresolved() {
    let dest = destination().await;
    // socks5:// as well as socks5h://: a client that looked the name up itself
    // would fail on `.invalid` before it reached the proxy.
    for scheme in ["socks5h", "socks5", "SOCKS5"] {
        let p = socks5(Some(("user", "p@ss word"))).await;
        let c = client(
            &proxy(format!(
                "{scheme}://user:p%40ss%20word@127.0.0.1:{}",
                p.port
            )),
            ClientConfig::default(),
        )
        .expect("a SOCKS5 proxy URL builds");
        let (status, body) = get(&c, &format!("http://{NAME}:{}/via", dest.port))
            .await
            .unwrap_or_else(|e| panic!("{scheme}: {e}"));
        assert_eq!((status, body.as_str()), (200, BODY), "{scheme}");
        let seen = only(&p);
        assert_eq!(seen.how, "socks5", "{scheme}");
        assert!(
            seen.name,
            "{scheme}: the name was resolved before the proxy"
        );
        assert_eq!((seen.host.as_str(), seen.port), (NAME, dest.port));
        assert_eq!(seen.user.as_deref(), Some("user"));
        assert_eq!(seen.pass.as_deref(), Some("p@ss word"));
        assert_eq!(seen.request, "GET /via HTTP/1.1", "{scheme}");
    }
    assert_eq!(dest.connections(), 0, "a request went around the proxy");
}

#[tokio::test]
async fn an_address_destination_goes_to_the_proxy_too() {
    // A destination this machine could reach directly, so going around the proxy
    // would show at the destination.
    let dest = destination().await;
    let p = socks5(None).await;
    let c = client(
        &proxy(format!("socks5h://127.0.0.1:{}", p.port)),
        ClientConfig::default(),
    )
    .unwrap();
    let (status, _) = get(&c, &format!("http://127.0.0.1:{}/", dest.port))
        .await
        .unwrap();
    assert_eq!(status, 200);
    let seen = only(&p);
    assert_eq!((seen.host.as_str(), seen.name), ("127.0.0.1", false));
    assert_eq!(dest.connections(), 0, "the request went around the proxy");
}

#[tokio::test]
async fn socks4_sends_the_name_as_socks4a() {
    let dest = destination().await;
    for scheme in ["socks4", "socks4a"] {
        let p = socks4().await;
        let c = client(
            &proxy(format!("{scheme}://127.0.0.1:{}", p.port)),
            ClientConfig::default(),
        )
        .expect("a SOCKS4 proxy URL builds");
        let (status, _) = get(&c, &format!("http://{NAME}:{}/", dest.port))
            .await
            .unwrap_or_else(|e| panic!("{scheme}: {e}"));
        assert_eq!(status, 200);
        let seen = only(&p);
        assert_eq!(seen.how, "socks4");
        assert!(
            seen.name,
            "{scheme}: the name was resolved before the proxy"
        );
        assert_eq!((seen.host.as_str(), seen.port), (NAME, dest.port));
    }
    assert_eq!(dest.connections(), 0);
}

#[tokio::test]
async fn an_http_proxy_gets_the_request_with_its_credentials() {
    let dest = destination().await;
    let p = http(Answer::Open).await;
    let c = client(
        &proxy(format!("http://user:secret@127.0.0.1:{}", p.port)),
        ClientConfig::default(),
    )
    .unwrap();
    let (status, _) = get(&c, &format!("http://{NAME}:{}/x", dest.port))
        .await
        .unwrap();
    assert_eq!(status, 200);
    let seen = only(&p);
    assert_eq!(seen.how, "forward");
    assert_eq!((seen.host.as_str(), seen.port), (NAME, dest.port));
    assert_eq!(
        seen.proxy_authorization.as_deref(),
        Some(basic("user", "secret").as_str())
    );
    assert_eq!(dest.connections(), 0);
}

#[tokio::test]
async fn a_dead_proxy_fails_the_request_and_nothing_goes_direct() {
    let dest = destination().await;
    for scheme in ["socks5h", "socks4a", "http"] {
        let c = client(
            &proxy(format!("{scheme}://127.0.0.1:{}", closed_port())),
            ClientConfig::default(),
        )
        .unwrap();
        let r = get(&c, &format!("http://127.0.0.1:{}/", dest.port)).await;
        assert!(r.is_err(), "{scheme}: sent with the proxy down: {r:?}");
    }
    assert_eq!(dest.connections(), 0, "a request went direct");
}

#[tokio::test]
async fn a_client_that_pins_names_cannot_send_through_a_proxy() {
    let p = socks5(None).await;
    let dest = destination().await;
    let built = client(
        &proxy(format!("socks5h://127.0.0.1:{}", p.port)),
        ClientConfig {
            resolve: vec![(NAME.to_string(), dest.addr())],
            ..Default::default()
        },
    );
    match built {
        Err(BuildError::Egress(m)) => assert!(m.contains("pinned"), "{m}"),
        other => panic!("built: {:?}", other.map(|_| ())),
    }
}

#[tokio::test]
async fn under_a_proxy_the_private_address_check_is_the_proxys() {
    // A node's gateway resolves and vets the name for such a client, so the client
    // hands it over rather than refusing to build.
    let p = socks5(None).await;
    let c = client(
        &proxy(format!("socks5h://127.0.0.1:{}", p.port)),
        ClientConfig {
            block_internal: true,
            ..Default::default()
        },
    )
    .expect("builds");
    let (status, _) = get(&c, &format!("http://{NAME}:8080/")).await.unwrap();
    assert_eq!(status, 200);
    assert_eq!(only(&p).host, NAME);
}

#[test]
fn an_unusable_proxy_url_never_builds_and_is_never_quoted() {
    for url in [
        "ftp://user:hunter2@127.0.0.1:21",
        "socks5://user:hunter2@",
        "http://user:hunter2@127.0.0.1:0",
        "user:hunter2@127.0.0.1:3128",
    ] {
        match client(&proxy(url.into()), ClientConfig::default()) {
            Err(BuildError::Egress(m)) => assert!(!m.contains("hunter2"), "{url}: {m}"),
            other => panic!("{url}: built: {:?}", other.map(|_| ())),
        }
    }
}

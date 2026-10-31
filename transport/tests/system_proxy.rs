//! A proxy named in the environment resolves the destination itself, so the
//! private-address filter and the pinned addresses would never be consulted.
//! A client that asks for either must not use one, and a client built for
//! `Egress::Direct` uses none at all.
//!
//! This is a test binary of its own because it sets HTTP_PROXY for the whole
//! process, which would reach every other test running beside it.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use transport::{ClientConfig, Egress, Redirect, build_client};

/// A listener that answers 200 to anything and counts what reached it.
fn counting_listener() -> (u16, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let seen = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&seen);
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { return };
            let mut buf = [0u8; 4096];
            if s.read(&mut buf).unwrap_or(0) > 0 {
                count.fetch_add(1, Ordering::SeqCst);
                let _ = s.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
            }
        }
    });
    (port, seen)
}

fn client(cfg: ClientConfig) -> transport::Client {
    build_client(
        ClientConfig {
            timeout: Some(Duration::from_secs(5)),
            redirect: Redirect::None,
            ..cfg
        },
        &Egress::Inherit,
    )
    .unwrap()
}

#[tokio::test]
async fn a_client_with_pins_or_the_internal_filter_ignores_a_proxy_in_the_environment() {
    let (proxy_port, via_proxy) = counting_listener();
    let (target_port, direct) = counting_listener();
    // SAFETY: the only test in this binary, so no other thread reads the
    // environment while it changes.
    unsafe {
        for name in [
            "HTTPS_PROXY",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
            "NO_PROXY",
            "no_proxy",
            "CROSSFYRE_EGRESS_PROXY",
        ] {
            std::env::remove_var(name);
        }
        std::env::set_var("HTTP_PROXY", format!("http://127.0.0.1:{proxy_port}"));
        std::env::set_var("http_proxy", format!("http://127.0.0.1:{proxy_port}"));
    }

    // A plain client still goes through it, so the fixture is sound and the
    // default is unchanged.
    let r = client(ClientConfig::default())
        .get(format!("http://pinned.test:{target_port}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    assert_eq!(via_proxy.load(Ordering::SeqCst), 1);

    // A pinned name is dialled at its pin.
    let pinned = client(ClientConfig {
        resolve: vec![(
            "pinned.test".into(),
            format!("127.0.0.1:{target_port}").parse().unwrap(),
        )],
        ..Default::default()
    });
    let r = pinned
        .get(format!("http://pinned.test:{target_port}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    assert_eq!(direct.load(Ordering::SeqCst), 1, "the pin was not dialled");
    assert_eq!(
        via_proxy.load(Ordering::SeqCst),
        1,
        "the proxy carried a pinned request"
    );

    // A name that resolves to loopback is refused rather than handed to the proxy.
    let filtered = client(ClientConfig {
        block_internal: true,
        ..Default::default()
    });
    let r = filtered
        .get(format!("http://localhost:{target_port}/"))
        .send()
        .await;
    assert!(r.is_err(), "sent: {:?}", r.map(|r| r.status()));
    assert_eq!(
        via_proxy.load(Ordering::SeqCst),
        1,
        "the proxy carried a filtered request"
    );
    assert_eq!(direct.load(Ordering::SeqCst), 1);

    // An address goes through the proxy too, for a client that names no egress...
    let to_address = format!("http://127.0.0.1:{target_port}/");
    let r = client(ClientConfig::default())
        .get(&to_address)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    assert_eq!(via_proxy.load(Ordering::SeqCst), 2);

    // ...and not for one built to go direct.
    let direct_client = build_client(
        ClientConfig {
            timeout: Some(Duration::from_secs(5)),
            redirect: Redirect::None,
            ..Default::default()
        },
        &Egress::Direct,
    )
    .unwrap();
    let r = direct_client.get(&to_address).send().await.unwrap();
    assert_eq!(r.status().as_u16(), 200);
    assert_eq!(
        via_proxy.load(Ordering::SeqCst),
        2,
        "the proxy carried a request built to go direct"
    );
    assert_eq!(direct.load(Ordering::SeqCst), 2);
}

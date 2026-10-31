//! [`Egress::Inherit`] and `CROSSFYRE_EGRESS_PROXY`: an engine run on its own sends
//! through the proxy the variable names, a value that cannot be used stops it
//! rather than letting it send from this machine, and a client the proxy would
//! undermine is refused.
//!
//! This is a test binary of its own, with one test, because it sets the variable
//! for the whole process.

mod common;

use std::io::ErrorKind;
use std::time::Duration;

use common::{BODY, NAME, destination, fetch_over, socks5};
use transport::{BuildError, ClientConfig, EGRESS_PROXY_VAR, Egress, Redirect, build_client, dial};

const QUICK: Duration = Duration::from_secs(3);

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

fn egress_error(built: Result<transport::Client, BuildError>) -> String {
    match built {
        Err(BuildError::Egress(m)) => m,
        other => panic!("built: {:?}", other.map(|_| ())),
    }
}

fn set(value: Option<&str>) {
    // SAFETY: the only test in this binary, and no request is in flight while the
    // variable changes, so nothing else reads the environment meanwhile.
    unsafe {
        match value {
            Some(v) => std::env::set_var(EGRESS_PROXY_VAR, v),
            None => std::env::remove_var(EGRESS_PROXY_VAR),
        }
    }
}

#[tokio::test]
async fn inherit_follows_crossfyre_egress_proxy_and_fails_closed() {
    // SAFETY: as in `set`.
    unsafe {
        for name in [
            "HTTP_PROXY",
            "http_proxy",
            "HTTPS_PROXY",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
            "NO_PROXY",
            "no_proxy",
        ] {
            std::env::remove_var(name);
        }
    }
    let dest = destination().await;
    let direct = format!("http://127.0.0.1:{}/", dest.port);
    let p = socks5(None).await;

    // A value that is not a usable proxy URL stops every client and every dial. It
    // used to be printed and ignored, and the request went out directly.
    for bad in [
        "bogus://user:hunter2@127.0.0.1:1",
        "127.0.0.1:3128",
        "socks5://user:hunter2@",
    ] {
        set(Some(bad));
        let m = egress_error(client(&Egress::Inherit, ClientConfig::default()));
        assert!(m.contains(EGRESS_PROXY_VAR), "{bad}: {m}");
        assert!(!m.contains("hunter2"), "{bad}: {m}");
        let e = dial(&Egress::Inherit, "127.0.0.1", dest.port, false, QUICK, None)
            .await
            .err()
            .unwrap_or_else(|| panic!("{bad}: dialled"));
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{bad}: {e}");
        assert!(!e.to_string().contains("hunter2"), "{bad}: {e}");
    }
    assert_eq!(dest.connections(), 0, "a bad value let something go direct");

    // A SOCKS URL is honoured, and a name goes to the proxy unresolved even when the
    // value says socks5:// rather than socks5h://.
    set(Some(&format!("socks5://127.0.0.1:{}", p.port)));
    let c = client(&Egress::Inherit, ClientConfig::default()).expect("builds");
    let r = c
        .get(format!("http://{NAME}:{}/", dest.port))
        .send()
        .await
        .expect("sent through the proxy");
    assert_eq!(r.status().as_u16(), 200);
    let r = c.get(&direct).send().await.expect("sent through the proxy");
    assert_eq!(r.status().as_u16(), 200);
    let mut t = dial(&Egress::Inherit, NAME, 443, false, QUICK, None)
        .await
        .expect("dialled through the proxy");
    assert!(fetch_over(&mut t).await.ends_with(BODY));
    let seen: Vec<(String, bool)> = p.seen().into_iter().map(|s| (s.host, s.name)).collect();
    assert_eq!(
        seen,
        [
            (NAME.to_string(), true),
            ("127.0.0.1".to_string(), false),
            (NAME.to_string(), true)
        ]
    );
    assert_eq!(dest.connections(), 0, "a request went around the proxy");

    // A client that refuses private addresses or pins names is refused, not sent
    // around the proxy: the proxy would look the name up where neither check sees.
    let m = egress_error(client(
        &Egress::Inherit,
        ClientConfig {
            block_internal: true,
            ..Default::default()
        },
    ));
    assert!(m.contains("private addresses"), "{m}");
    let m = egress_error(client(
        &Egress::Inherit,
        ClientConfig {
            resolve: vec![(NAME.to_string(), dest.addr())],
            ..Default::default()
        },
    ));
    assert!(m.contains("pinned"), "{m}");
    for (block_internal, pin) in [(true, None), (false, Some(dest.addr()))] {
        let e = dial(
            &Egress::Inherit,
            NAME,
            dest.port,
            block_internal,
            QUICK,
            pin,
        )
        .await
        .err()
        .unwrap_or_else(|| panic!("dialled with block_internal {block_internal}, pin {pin:?}"));
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e}");
    }
    assert_eq!(p.seen().len(), 3, "a refused client reached the proxy");
    assert_eq!(dest.connections(), 0, "a refused client went direct");

    // Direct reads none of it.
    let c = client(&Egress::Direct, ClientConfig::default()).unwrap();
    assert_eq!(c.get(&direct).send().await.unwrap().status().as_u16(), 200);
    let mut t = dial(&Egress::Direct, "127.0.0.1", dest.port, false, QUICK, None)
        .await
        .unwrap();
    assert!(fetch_over(&mut t).await.ends_with(BODY));
    assert_eq!(dest.connections(), 2);

    // Unset, Inherit is what it always was.
    set(None);
    let c = client(&Egress::Inherit, ClientConfig::default()).unwrap();
    assert_eq!(c.get(&direct).send().await.unwrap().status().as_u16(), 200);
    let mut t = dial(&Egress::Inherit, "127.0.0.1", dest.port, false, QUICK, None)
        .await
        .unwrap();
    assert!(fetch_over(&mut t).await.ends_with(BODY));
    assert_eq!(dest.connections(), 4);
    assert_eq!(
        p.seen().len(),
        3,
        "the proxy was used with the variable unset"
    );
}

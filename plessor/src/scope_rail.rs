//! Every engine that takes an endpoint list keeps to the scan's scope.
//!
//! The injection pass checked each endpoint's host against the target and the
//! operator's scope list before sending anything at it. Structure fuzzing,
//! request-shape discovery and authorization testing take the same kind of list
//! and checked nothing, so an endpoint on another host was tested as readily as
//! one on the target. The platform builds those lists from recorded operations,
//! and a recording can hold a host the operator never named.
//!
//! Two listeners: the target, and one reachable under a different host name that
//! is not on any scope list. Each engine is handed one endpoint on each. Nothing
//! may arrive at the second, and something must arrive at the first, so the test
//! cannot pass on an engine that has stopped sending anything.

use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

/// A listener that answers every request with a small JSON object and counts them.
async fn counting(bind: &str) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind(bind).await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let seen = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let seen = Arc::clone(&counter);
            tokio::spawn(async move {
                let mut buf = [0u8; 16384];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(_) => {
                            seen.fetch_add(1, Ordering::SeqCst);
                            let body = br#"{"ok":true,"id":1,"role":"user","email":"a@b.test"}"#;
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                                 Content-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                                body.len()
                            );
                            if sock.write_all(resp.as_bytes()).await.is_err()
                                || sock.write_all(body).await.is_err()
                            {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    (port, seen)
}

/// (requests at the target, requests at the off-scope host) for one engine run.
async fn split<F, Fut>(run: F) -> (usize, usize)
where
    F: FnOnce(String, String, mpsc::UnboundedSender<serde_json::Value>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let (tport, tseen) = counting("127.0.0.1:0").await;
    let (oport, oseen) = counting("127.0.0.1:0").await;
    // Same machine, different name: 127.0.0.1 is the target, localhost is not.
    let target = format!("http://127.0.0.1:{tport}");
    let other = format!("http://localhost:{oport}");
    let (tx, mut rx) = mpsc::unbounded_channel();
    run(target, other, tx).await;
    while rx.try_recv().is_ok() {}
    (tseen.load(Ordering::SeqCst), oseen.load(Ordering::SeqCst))
}

fn typed(base: &str) -> serde_json::Value {
    json!({
        "method": "POST",
        "url": format!("{base}/api/v1/profile"),
        "body": [{"name": "name", "value": "x"}, {"name": "age", "value": "3"}],
        "body_type": "json"
    })
}

async fn fuzz(target: String, other: String, tx: mpsc::UnboundedSender<serde_json::Value>) {
    let params = serde_json::from_value(json!({
        "target": target, "evasive": false, "timeout_ms": 2000,
        "endpoints": [typed(&target), typed(&other)],
    }))
    .expect("fuzz params");
    crate::fuzz::run(params, tx).await;
}

async fn discover(target: String, other: String, tx: mpsc::UnboundedSender<serde_json::Value>) {
    let ep = |b: &str| json!({"method": "POST", "url": format!("{b}/api/v1/profile"), "content_type": "json"});
    let params = serde_json::from_value(json!({
        "target": target, "evasive": false, "timeout_ms": 2000,
        "endpoints": [ep(&target), ep(&other)],
    }))
    .expect("discover params");
    crate::discover::run(params, tx).await;
}

async fn authz(target: String, other: String, tx: mpsc::UnboundedSender<serde_json::Value>) {
    let ep = |b: &str| json!({"method": "GET", "url": format!("{b}/api/v1/users/1")});
    let params = serde_json::from_value(json!({
        "target": target, "timeout_ms": 2000, "evasive": false,
        "endpoints": [ep(&target), ep(&other)],
        "identities": [
            {"role": "admin", "auth": {"headers": {"Authorization": "Bearer admin-token"}}},
            {"role": "user", "auth": {"headers": {"Authorization": "Bearer user-token"}}},
        ],
    }))
    .expect("authz params");
    crate::authz::run(params, tx).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn no_engine_sends_anything_to_a_host_outside_the_scope() {
    let cases = vec![
        ("fuzz", split(fuzz).await),
        ("discover", split(discover).await),
        ("authz", split(authz).await),
    ];
    let leaked: Vec<String> = cases
        .iter()
        .filter(|(_, (_, off))| *off > 0)
        .map(|(name, (_, off))| format!("{name} sent {off} to the off-scope host"))
        .collect();
    assert!(leaked.is_empty(), "{}", leaked.join(", "));
    for (name, (on, _)) in &cases {
        // The open build's authorization engine is a stub that sends nothing at
        // all, so only its off-scope half means anything there.
        if *name == "authz" && !cfg!(authz_private) {
            continue;
        }
        assert!(
            *on > 0,
            "{name} sent nothing to the target either, so this proves nothing about it"
        );
    }
}

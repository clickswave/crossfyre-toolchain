//! One test for the rule that five engines each had to learn separately.
//!
//! Every operation that takes a caller-supplied endpoint list replays the method
//! it is given. For `DELETE`, `PUT` and `PATCH` the request IS the damage, so
//! sending one is never a test of whether it could be sent, and the default has
//! to be not to. Both authorization engines carried that rail. Injection,
//! discovery and structure fuzzing did not, and the rule was sitting in prose
//! beside the engines that had it the whole time: `names_an_action` argues in
//! full that testing a button "can also log the scan out, harden the target, or
//! delete a customer's data; the second outcome is not worth the first", three
//! hundred lines from code that sent 118 DELETE requests at a record.
//!
//! So this does not test any engine's reasoning. It counts requests arriving at
//! a socket, which is the only thing that was ever in question, and it asserts
//! BOTH directions: nothing with the rail up, and something with it down. The
//! second half is what stops this passing on an engine that has quietly stopped
//! working, which is the failure a safety test is least able to notice.
//!
//! Adding an operation that takes endpoints means adding it here.

use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

/// A listener that answers everything and counts what it was asked.
///
/// Returns its address and the counter. It answers a small JSON body so an
/// engine gets far enough to try everything it has, and it keeps serving until
/// the test drops it.
async fn counting_target() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let seen = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let seen = Arc::clone(&counter);
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                loop {
                    // One read per request is enough: nothing here pipelines,
                    // and a partial read still means a request was sent, which
                    // is the thing being counted.
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(_) => {
                            seen.fetch_add(1, Ordering::SeqCst);
                            let body = br#"{"ok":true,"id":1,"role":"user"}"#;
                            let head = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                                 Content-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                                body.len()
                            );
                            if sock.write_all(head.as_bytes()).await.is_err()
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
    (format!("http://{addr}"), seen)
}

/// Run one operation to completion and report how many requests reached the
/// target.
async fn requests_sent<F, Fut>(op: F) -> usize
where
    F: FnOnce(String, mpsc::UnboundedSender<serde_json::Value>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let (base, seen) = counting_target().await;
    let (tx, mut rx) = mpsc::unbounded_channel();
    op(base, tx).await;
    // Drain, so a full channel can never be what ended the pass.
    while rx.try_recv().is_ok() {}
    seen.load(Ordering::SeqCst)
}

/// The endpoint every case uses: a method that destroys, a path id declared as a
/// parameter, and a body shape, so nothing is skipped for want of something to
/// work with.
fn delete_endpoint(base: &str) -> serde_json::Value {
    json!({
        "method": "DELETE",
        "url": format!("{base}/api/v1/records/42"),
        "path_params": [3],
        "body": [{"name": "note", "value": "x"}],
        "body_type": "json"
    })
}

async fn inject_run(base: String, tx: mpsc::UnboundedSender<serde_json::Value>, writes: bool) {
    let params = serde_json::from_value(json!({
        "target": base, "evasive": false, "timeout_ms": 2000, "tasks": 1,
        "test_writes": writes, "classes": ["sqli"],
        "endpoints": [delete_endpoint(&base)],
    }))
    .expect("inject params");
    crate::inject::run(params, tx).await;
}

async fn discover_run(base: String, tx: mpsc::UnboundedSender<serde_json::Value>, writes: bool) {
    let params = serde_json::from_value(json!({
        "target": base, "evasive": false, "timeout_ms": 2000,
        "test_writes": writes,
        "endpoints": [{
            "method": "DELETE",
            "url": format!("{base}/api/v1/records/42"),
            "content_type": "json",
        }],
    }))
    .expect("discover params");
    crate::discover::run(params, tx).await;
}

async fn fuzz_run(base: String, tx: mpsc::UnboundedSender<serde_json::Value>, writes: bool) {
    let params = serde_json::from_value(json!({
        "target": base, "evasive": false, "timeout_ms": 2000,
        "test_writes": writes,
        "endpoints": [delete_endpoint(&base)],
    }))
    .expect("fuzz params");
    crate::fuzz::run(params, tx).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn no_engine_sends_a_destroying_method_by_default() {
    // Measured before the rails went in: inject 118 requests and the record
    // gone, discover 59, fuzz 4.
    let cases: Vec<(&str, usize)> = vec![
        (
            "inject",
            requests_sent(|b, t| inject_run(b, t, false)).await,
        ),
        (
            "discover",
            requests_sent(|b, t| discover_run(b, t, false)).await,
        ),
        ("fuzz", requests_sent(|b, t| fuzz_run(b, t, false)).await),
    ];
    // Every engine reported, not just the first to fail. A developer who has
    // taken one rail down wants to know whether they took three down.
    let broke: Vec<String> = cases
        .iter()
        .filter(|(_, sent)| *sent > 0)
        .map(|(name, sent)| format!("{name} sent {sent}"))
        .collect();
    assert!(
        broke.is_empty(),
        "these sent requests at a DELETE endpoint with writes off: {}",
        broke.join(", ")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn and_every_one_of_them_still_works_when_asked() {
    // The half that stops the test above passing on an engine that has stopped
    // working. If a rail is the reason nothing was sent, taking it down has to
    // put the requests back.
    for (name, sent) in [
        ("inject", requests_sent(|b, t| inject_run(b, t, true)).await),
        (
            "discover",
            requests_sent(|b, t| discover_run(b, t, true)).await,
        ),
        ("fuzz", requests_sent(|b, t| fuzz_run(b, t, true)).await),
    ] {
        assert!(
            sent > 0,
            "{name} sent nothing even with writes ON, so the rail is not what was stopping it"
        );
    }
}

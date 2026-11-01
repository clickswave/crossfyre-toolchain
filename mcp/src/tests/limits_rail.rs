//! The brakes that do not depend on the model noticing it is in a loop.

use super::support::*;
use serde_json::json;

#[tokio::test]
async fn the_eleventh_call_in_a_burst_is_refused() {
    let t = scope(&["a.test".into()], "").calls(10, 60).build();
    let peer = FakePeer::new(Elicit::None);
    for _ in 0..10 {
        ok(&t.call(&peer, "get_scope", json!({})).await);
    }
    let r = t.call(&peer, "get_scope", json!({})).await;
    assert_eq!(reason(&r), "rate_limited");
    assert!(r.text.contains("retry_after_seconds"));
    assert_eq!(
        t.audit_lines().len(),
        11,
        "a refused call is still recorded"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn running_scans_are_capped() {
    let target = listener(Reply::ok("x")).await;
    let plessor = stub_engine(StubOpts {
        cancellable: true,
        hold: true,
        ..Default::default()
    })
    .await;
    let t = scope(
        &[format!("127.0.0.1:{}", target.port)],
        "max_concurrent_scans = 1",
    )
    .plessor(plessor.port)
    .build();
    let peer = FakePeer::new(Elicit::None);
    let args = json!({"url": format!("http://127.0.0.1:{}/?q=1", target.port)});
    let id = ok(&t.call(&peer, "test_injection", args.clone()).await)["scan_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        reason(&t.call(&peer, "test_injection", args.clone()).await),
        "scan_limit"
    );
    assert_eq!(plessor.ops().len(), 1);
    ok(&t.call(&peer, "cancel_scan", json!({"scan_id": id})).await);
    ok(&t.call(&peer, "test_injection", args).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scan_starts_are_capped_per_hour() {
    let target = listener(Reply::ok("x")).await;
    let plessor = stub_engine(StubOpts::default()).await;
    let t = scope(
        &[format!("127.0.0.1:{}", target.port)],
        "max_scan_starts_per_hour = 1",
    )
    .plessor(plessor.port)
    .build();
    let peer = FakePeer::new(Elicit::None);
    let args = json!({"url": format!("http://127.0.0.1:{}/?q=1", target.port), "wait_seconds": 5});
    assert_eq!(
        ok(&t.call(&peer, "test_injection", args.clone()).await)["status"],
        "completed"
    );
    assert_eq!(
        reason(&t.call(&peer, "test_injection", args).await),
        "scan_limit"
    );
    assert_eq!(plessor.ops().len(), 1);
}

#[tokio::test]
async fn the_refusal_states_the_limits_in_force() {
    let t = scope(&["a.test".into()], "").calls(5, 30).build();
    let peer = FakePeer::new(Elicit::None);
    for _ in 0..5 {
        ok(&t.call(&peer, "get_scope", json!({})).await);
    }
    let r = t.call(&peer, "get_scope", json!({})).await;
    assert_eq!(reason(&r), "rate_limited");
    assert!(
        r.text.contains("30 a minute") && r.text.contains("up to 5"),
        "{}",
        r.text
    );
}

#[tokio::test]
async fn an_unknown_tool_is_unknown_whatever_the_bucket_holds() {
    let t = scope(&["a.test".into()], "").calls(1, 1).build();
    let peer = FakePeer::new(Elicit::None);
    ok(&t.call(&peer, "get_scope", json!({})).await);
    let r = t.call(&peer, "no_such_tool", json!({})).await;
    assert_eq!(reason(&r), "unknown_tool", "{}", r.text);
}

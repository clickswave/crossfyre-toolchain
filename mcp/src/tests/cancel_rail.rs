//! Stopping a scan says what actually happened.
//!
//! `stopped` is a claim that the engine stopped, so it is made only when the engine
//! said so. An engine that cannot be stopped gets `requested`, and a call cancelled
//! before it handed out its scan handle takes the scan with it, because nobody else
//! could stop it.

use super::support::*;
use serde_json::json;
use tokio_util::sync::CancellationToken;

async fn start(t: &TestMcp, peer: &FakePeer, port: u16) -> String {
    let r = t
        .call(
            peer,
            "test_injection",
            json!({"url": format!("http://127.0.0.1:{port}/?q=1")}),
        )
        .await;
    let v = ok(&r);
    assert_eq!(v["status"], "running", "{v}");
    v["scan_id"].as_str().unwrap().to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancellable_engine_is_stopped() {
    let target = listener(Reply::ok("x")).await;
    let plessor = stub_engine(StubOpts {
        cancellable: true,
        hold: true,
        ..Default::default()
    })
    .await;
    let t = scope(&[format!("127.0.0.1:{}", target.port)], "")
        .plessor(plessor.port)
        .build();
    let peer = FakePeer::new(Elicit::None);
    let id = start(&t, &peer, target.port).await;
    let v = ok(&t.call(&peer, "cancel_scan", json!({"scan_id": id})).await).clone();
    assert_eq!(v["cancel"], "stopped", "{v}");
    assert_eq!(v["status"], "cancelled");
    assert_eq!(plessor.cancels(), 1, "the engine never saw the cancel line");
    let g = ok(&t.call(&peer, "get_scan", json!({"scan_id": id})).await).clone();
    assert_eq!(
        (g["status"].as_str(), g["cancel"].as_str()),
        (Some("cancelled"), Some("stopped"))
    );
    // Again, once it has ended: the same answer, and nothing sent.
    let v = ok(&t.call(&peer, "cancel_scan", json!({"scan_id": id})).await).clone();
    assert_eq!(v["status"], "cancelled");
    assert!(v["cancel"].is_null());
    assert_eq!(plessor.cancels(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_engine_that_cannot_stop_is_reported_as_requested() {
    let target = listener(Reply::ok("x")).await;
    let plessor = stub_engine(StubOpts {
        cancellable: false,
        hold: true,
        ..Default::default()
    })
    .await;
    let t = scope(&[format!("127.0.0.1:{}", target.port)], "")
        .plessor(plessor.port)
        .build();
    let peer = FakePeer::new(Elicit::None);
    let id = start(&t, &peer, target.port).await;
    let v = ok(&t.call(&peer, "cancel_scan", json!({"scan_id": id})).await).clone();
    assert_eq!(v["cancel"], "requested", "{v}");
    assert!(v["note"].as_str().unwrap().contains("update the engine"));
    let g = ok(&t.call(&peer, "get_scan", json!({"scan_id": id})).await).clone();
    assert_eq!(g["cancel"], "requested");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_call_cancelled_while_waiting_cancels_its_scan() {
    let target = listener(Reply::ok("x")).await;
    let plessor = stub_engine(StubOpts {
        cancellable: true,
        hold: true,
        ..Default::default()
    })
    .await;
    let t = scope(&[format!("127.0.0.1:{}", target.port)], "")
        .plessor(plessor.port)
        .build();
    let peer = FakePeer::new(Elicit::None);
    let ct = CancellationToken::new();
    let stop = ct.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        stop.cancel();
    });
    let started = std::time::Instant::now();
    let r = t
        .call_ct(
            &peer,
            "test_injection",
            json!({"url": format!("http://127.0.0.1:{}/?q=1", target.port), "wait_seconds": 30}),
            ct,
        )
        .await;
    assert_eq!(reason(&r), "cancelled");
    assert!(started.elapsed().as_secs() < 10);
    assert_eq!(plessor.cancels(), 1);
    let line = t.audit_lines().into_iter().last().unwrap();
    assert_eq!(line["decision"], "cancelled");
    let id = line["scan_id"].as_str().unwrap().to_string();
    assert_eq!(t.mcp.jobs.read_meta(&id).unwrap().status, "cancelled");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stopping_the_server_marks_its_scans_interrupted() {
    let target = listener(Reply::ok("x")).await;
    let plessor = stub_engine(StubOpts {
        cancellable: true,
        hold: true,
        ..Default::default()
    })
    .await;
    let t = scope(&[format!("127.0.0.1:{}", target.port)], "")
        .plessor(plessor.port)
        .build();
    let peer = FakePeer::new(Elicit::None);
    let id = start(&t, &peer, target.port).await;
    t.mcp.shutdown().await;
    let m = t.mcp.jobs.read_meta(&id).unwrap();
    assert_eq!(m.status, "interrupted");
    assert_eq!(m.error.as_deref(), Some("server stopped"));
    eventually("the cancel line", 3, || plessor.cancels() == 1).await;
}

#[tokio::test]
async fn a_fingerprint_still_in_progress_is_not_reported_as_ended() {
    let t = scope(&["a.test".into()], "").build();
    let meta = crate::jobs::JobMeta::new(
        &t.mcp.session,
        crate::jobs::NewJob {
            tool: "fingerprint",
            engine: "toolmark",
            target: "http://a.test/",
            endpoints: Vec::new(),
            scope_sha256: None,
            cancellable: false,
            test_writes: false,
        },
    );
    assert_eq!(meta.status, "running");
    t.mcp.jobs.write_meta(&meta).unwrap();
    let r = t
        .call(
            &FakePeer::new(Elicit::None),
            "cancel_scan",
            json!({"scan_id": meta.id}),
        )
        .await;
    assert_eq!(reason(&r), "invalid_arguments", "{}", r.text);
    assert!(r.text.contains("still in progress"), "{}", r.text);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_call_still_open_when_the_server_stops_gets_its_audit_line() {
    let target = listener(Reply::ok("x")).await;
    let plessor = stub_engine(StubOpts {
        cancellable: true,
        hold: true,
        ..Default::default()
    })
    .await;
    let t = std::sync::Arc::new(
        scope(&[format!("127.0.0.1:{}", target.port)], "")
            .plessor(plessor.port)
            .build(),
    );
    let t2 = std::sync::Arc::clone(&t);
    let port = target.port;
    let call = tokio::spawn(async move {
        t2.call(
            &FakePeer::new(Elicit::None),
            "test_injection",
            json!({"url": format!("http://127.0.0.1:{port}/?q=1&token=abc123"), "wait_seconds": 30}),
        )
        .await
    });
    eventually("the scan to start", 5, || plessor.ops().len() == 1).await;
    eventually("the scan to be running", 5, || {
        t.mcp.running.lock().unwrap().len() == 1
    })
    .await;
    t.mcp.shutdown().await;

    let calls = |t: &TestMcp| -> Vec<serde_json::Value> {
        t.audit_lines()
            .into_iter()
            .filter(|l| l["event"] == "call")
            .collect()
    };
    let lines = calls(&t);
    assert_eq!(lines.len(), 1, "{lines:#?}");
    assert_eq!(lines[0]["tool"], "test_injection");
    assert_eq!(lines[0]["decision"], "interrupted");
    assert!(lines[0]["scan_id"].is_string(), "{}", lines[0]);
    assert!(!t.audit_text().contains("abc123"));

    // The call itself ends once its scan does, and does not write a second line.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(10), call).await;
    assert_eq!(calls(&t).len(), 1, "{:#?}", calls(&t));
}

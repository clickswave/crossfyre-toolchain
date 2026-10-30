//! The engines dial what the guard cleared, and go nowhere a target sends them.
//!
//! The server checks a name's addresses before anything is sent. An engine that looks
//! the name up again can be answered with an address the check dropped, and an engine
//! that follows redirects goes wherever the target points it. So each engine is given
//! the cleared address and told not to follow redirects, and a daemon too old to honour
//! either is not used at all.

use super::support::*;
use serde_json::json;
use std::collections::HashMap;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_engines_are_pinned_to_the_cleared_address_with_redirects_off() {
    // A public and a loopback address for one name: the check keeps the public one,
    // and that is the only one the engines may be given. Nothing is simulated, so
    // nothing here goes to the public address.
    let toolmark = stub_engine(StubOpts {
        events: toolmark_events("t", "s"),
        ..Default::default()
    })
    .await;
    let plessor = stub_engine(StubOpts::default()).await;
    let names = FakeResolver::default().with("mixed.test", &["93.184.216.34", "127.0.0.1"]);
    let t = scope(&["mixed.test".into()], "")
        .resolver(names)
        .toolmark(toolmark.port)
        .plessor(plessor.port)
        .build();
    let peer = FakePeer::new(Elicit::None);

    ok(&t
        .call(
            &peer,
            "fingerprint",
            json!({"url": "http://mixed.test:8080/"}),
        )
        .await);
    let op = &toolmark.ops()[0];
    assert_eq!(
        op["resolve"],
        json!([["mixed.test", "93.184.216.34:8080"]]),
        "{op}"
    );
    assert_eq!(op["follow_redirects"], false, "{op}");
    assert_eq!(op["block_internal"], true, "{op}");

    ok(&t
        .call(
            &peer,
            "test_injection",
            json!({"url": "http://mixed.test:8080/?q=1"}),
        )
        .await);
    let op = &plessor.ops()[0];
    assert_eq!(
        op["resolve"],
        json!([["mixed.test", "93.184.216.34:8080"]]),
        "{op}"
    );
    assert_eq!(op["follow_redirects"], false, "{op}");
    assert_eq!(op["block_internal"], true, "{op}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_address_needs_no_pin_and_still_gets_redirects_off() {
    let target = listener(Reply::ok("x")).await;
    let plessor = stub_engine(StubOpts::default()).await;
    let t = scope(&[format!("127.0.0.1:{}", target.port)], "")
        .plessor(plessor.port)
        .build();
    ok(&t
        .call(
            &FakePeer::new(Elicit::None),
            "test_injection",
            json!({"url": format!("http://127.0.0.1:{}/?q=1", target.port)}),
        )
        .await);
    let op = &plessor.ops()[0];
    assert_eq!(op["resolve"], json!([]), "{op}");
    assert_eq!(op["follow_redirects"], false, "{op}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_engine_too_old_to_be_fenced_is_not_used() {
    let target = listener(Reply::ok("x")).await;
    // Both would request the target if they were sent an operation.
    let toolmark = stub_engine(StubOpts {
        old: true,
        events: toolmark_events("t", "s"),
        simulate: Some(HashMap::new()),
        ..Default::default()
    })
    .await;
    let plessor = stub_engine(StubOpts {
        old: true,
        simulate: Some(HashMap::new()),
        ..Default::default()
    })
    .await;
    let t = scope(&[format!("127.0.0.1:{}", target.port)], "")
        .toolmark(toolmark.port)
        .plessor(plessor.port)
        .build();
    let peer = FakePeer::new(Elicit::Accept);
    for (tool, args) in [
        (
            "fingerprint",
            json!({"url": format!("http://127.0.0.1:{}/", target.port)}),
        ),
        (
            "test_injection",
            json!({"url": format!("http://127.0.0.1:{}/?q=1", target.port)}),
        ),
    ] {
        let r = t.call(&peer, tool, args).await;
        assert_eq!(reason(&r), "engine_unavailable", "{tool}: {}", r.text);
        assert!(r.text.contains("restart"), "{}", r.text);
    }
    assert!(toolmark.ops().is_empty() && plessor.ops().is_empty());
    assert_eq!(target.conns(), 0);
    assert_eq!(
        peer.asked(),
        0,
        "nobody is asked about traffic to an engine that will not be used"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_body_field_without_a_value_is_sent_in_the_shape_plessor_reads() {
    // plessor's own definition of a body field: a missing value is an empty string,
    // and a null is an error that fails the whole operation.
    #[derive(serde::Deserialize)]
    #[allow(dead_code)]
    struct BodyField {
        name: String,
        #[serde(default)]
        value: String,
        #[serde(default, rename = "type")]
        ty: Option<String>,
    }
    let target = listener(Reply::ok("x")).await;
    let plessor = stub_engine(StubOpts::default()).await;
    let t = scope(&[format!("127.0.0.1:{}", target.port)], "")
        .plessor(plessor.port)
        .build();
    ok(&t
        .call(
            &FakePeer::new(Elicit::None),
            "test_injection",
            json!({"endpoints": [{
                "url": format!("http://127.0.0.1:{}/form", target.port),
                "method": "POST",
                "body": [{"name": "q"}, {"name": "n", "value": "1", "type": "integer"}],
            }]}),
        )
        .await);
    let body = plessor.ops()[0]["endpoints"][0]["body"].clone();
    let fields: Vec<BodyField> =
        serde_json::from_value(body.clone()).unwrap_or_else(|e| panic!("{e}: {body}"));
    assert_eq!(fields[0].value, "");
    assert_eq!(fields[1].ty.as_deref(), Some("integer"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn progress_only_ever_goes_up() {
    let target = listener(Reply::ok("x")).await;
    let url = format!("http://127.0.0.1:{}/?q=1", target.port);
    let finding = |n: u32| {
        json!({"type": "finding", "data": {"vuln_class": "xss", "severity": "LOW",
            "name": format!("reflected {n}"), "url": url, "param": "q"}})
    };
    let plessor = stub_engine(StubOpts {
        events: vec![
            json!({"type": "progress", "processed": 0, "total": 12}),
            finding(1),
            finding(2),
            json!({"type": "progress", "processed": 3, "total": 12}),
        ],
        delay_ms: 600,
        ..Default::default()
    })
    .await;
    let t = scope(&[format!("127.0.0.1:{}", target.port)], "")
        .plessor(plessor.port)
        .build();
    let peer = FakePeer::new(Elicit::None);
    ok(&t
        .call(
            &peer,
            "test_injection",
            json!({"url": url, "wait_seconds": 10}),
        )
        .await);
    let done: Vec<f64> = peer.progress.lock().unwrap().iter().map(|p| p.0).collect();
    assert!(!done.is_empty(), "no progress was reported");
    assert!(
        done.windows(2).all(|w| w[1] > w[0]),
        "progress went sideways: {done:?}"
    );
}

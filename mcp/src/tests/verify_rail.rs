//! A finding checked again by its proof goes to plessor fenced as a scan is, only for a
//! finding in scope whose proof can be sent as it was kept, and a proof that can change
//! the target waits for test_writes, allow_writes and a yes.
//!
//! plessor is a stub that keeps the scans and findings it is seeded with and answers a
//! verify as the daemon does. Nothing is simulated, so nothing here leaves the machine.

use super::support::*;
use cfx_cve::inventory::NOT_PROOF;
use serde_json::{Value, json};

fn names() -> FakeResolver {
    FakeResolver::default()
        .with("app.test", &["93.184.216.34"])
        .with("other.test", &["93.184.216.35"])
}

/// A template finding's proof: `requests`, each `[method, url, header fields]`.
fn proof(requests: &[(&str, &str, Value)]) -> Value {
    json!({"format": 1, "engine": "plessor", "pack": "built in", "kind": "template",
           "check": "widget-version",
           "requests": requests.iter().map(|(m, u, f)| json!({"method": m, "url": u, "fields": f}))
               .collect::<Vec<_>>(),
           "matchers": [{"type": "word", "words": ["ok"]}],
           "fired": [{"matcher": "word", "part": "body", "evidence": "ok"}],
           "status": 200, "response_sha256": "5d41402abc4b2a76", "slots": []})
}

/// Keep a template scan of `target` in `stub`, with one finding of `data`; the finding's
/// id here.
fn seeded(stub: &Stub, target: &str, data: Value) -> String {
    let mut kept = stub.kept.lock().unwrap();
    let scan = kept.scan(
        target,
        "completed",
        json!({"operation": "scan"}),
        &now_utc(),
    );
    let id = kept.finding(&scan, data, &now_utc());
    format!("f_plessor_{id}")
}

fn template_finding(url: &str, proof: Value) -> Value {
    json!({"type": "vulnerability", "vuln_class": "exposure", "name": "widget version",
           "severity": "info", "template": "widget-version", "url": url, "proof": proof})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_finding_is_verified_pinned_and_unredirected() {
    let plessor = stub_engine(StubOpts::default()).await;
    let id = seeded(
        &plessor,
        "http://app.test/",
        template_finding(
            "http://app.test/about",
            proof(&[("GET", "http://app.test/about", json!([]))]),
        ),
    );
    let t = scope(&["app.test".into()], "")
        .resolver(names())
        .plessor(plessor.port)
        .build();
    let peer = FakePeer::new(Elicit::None);
    let r = t.call(&peer, "list_findings", json!({})).await;
    let listed = ok(&r)["findings"][0].clone();
    assert_eq!(listed["verifiable"], true, "{listed}");

    let r = t
        .call(&peer, "verify_finding", json!({"finding_id": id}))
        .await;
    let v = ok(&r).clone();
    assert_eq!(v["answer"], "reproduced", "{v}");
    assert_eq!(v["http_status"], 200);
    assert_eq!(v["target_data"]["untrusted"], true);
    assert_eq!(v["target_data"]["fired"][0]["evidence"], "ok");
    assert!(v.get("note").is_none(), "{v}");
    let op = &plessor.ops()[0];
    assert_eq!(op["operation"], "verify", "{op}");
    assert_eq!(op["finding"], 1, "{op}");
    assert_eq!(op["follow_redirects"], false, "{op}");
    assert_eq!(
        op["resolve"],
        json!([["app.test", "93.184.216.34:80"]]),
        "{op}"
    );
    assert_eq!(op["block_internal"], true, "{op}");
    assert_eq!(op["test_writes"], false, "{op}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn not_reproduced_says_it_is_not_proof_the_host_is_safe() {
    let plessor = stub_engine(StubOpts {
        verify: Some(
            json!({"status": "completed", "answer": "not reproduced", "fired": [],
                            "http_status": 404, "response_sha256": "ab"}),
        ),
        ..Default::default()
    })
    .await;
    let id = seeded(
        &plessor,
        "http://app.test/",
        template_finding(
            "http://app.test/about",
            proof(&[("GET", "http://app.test/about", json!([]))]),
        ),
    );
    let t = scope(&["app.test".into()], "")
        .resolver(names())
        .plessor(plessor.port)
        .build();
    let r = t
        .call(
            &FakePeer::new(Elicit::None),
            "verify_finding",
            json!({"finding_id": id}),
        )
        .await;
    let v = ok(&r);
    assert_eq!(v["answer"], "not reproduced");
    assert_eq!(v["note"], NOT_PROOF);
    assert!(r.text.contains(NOT_PROOF), "{}", r.text);
    assert!(!r.text.contains("not exploitable"), "{}", r.text);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_finding_or_a_proof_outside_the_scope_file_is_refused_unsent() {
    let plessor = stub_engine(StubOpts::default()).await;
    let elsewhere = seeded(
        &plessor,
        "http://other.test/",
        template_finding(
            "http://other.test/about",
            proof(&[("GET", "http://other.test/about", json!([]))]),
        ),
    );
    let sent_off = seeded(
        &plessor,
        "http://app.test/",
        template_finding(
            "http://app.test/about",
            proof(&[("GET", "http://other.test/about", json!([]))]),
        ),
    );
    let t = scope(&["app.test".into()], "")
        .resolver(names())
        .plessor(plessor.port)
        .build();
    let peer = FakePeer::new(Elicit::None);
    let r = t
        .call(&peer, "verify_finding", json!({"finding_id": elsewhere}))
        .await;
    assert_eq!(reason(&r), "not_found", "{}", r.text);
    let r = t
        .call(&peer, "verify_finding", json!({"finding_id": sent_off}))
        .await;
    assert_eq!(reason(&r), "out_of_scope", "{}", r.text);
    assert!(plessor.ops().is_empty(), "{:?}", plessor.ops());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_finding_that_cannot_be_sent_again_says_why() {
    let plessor = stub_engine(StubOpts {
        verify: Some(json!({"status": "error",
            "message": "not replayed: it needs auth.cookie, which was not given"})),
        ..Default::default()
    })
    .await;
    let injected = seeded(
        &plessor,
        "http://app.test/",
        json!({"type": "vulnerability", "vuln_class": "sqli", "severity": "high",
               "url": "http://app.test/?q=1", "param": "q"}),
    );
    let needs_a_session = seeded(
        &plessor,
        "http://app.test/",
        template_finding(
            "http://app.test/about",
            proof(&[("GET", "http://app.test/about", json!([]))]),
        ),
    );
    let t = scope(&["app.test".into()], "")
        .resolver(names())
        .plessor(plessor.port)
        .build();
    let peer = FakePeer::new(Elicit::None);
    let r = t
        .call(&peer, "verify_finding", json!({"finding_id": injected}))
        .await;
    assert_eq!(reason(&r), "not_verifiable", "{}", r.text);
    assert!(r.text.contains("no proof kept"), "{}", r.text);
    let r = t
        .call(
            &peer,
            "verify_finding",
            json!({"finding_id": "f_toolmark_1"}),
        )
        .await;
    assert_eq!(reason(&r), "not_verifiable", "{}", r.text);
    assert!(plessor.ops().is_empty(), "{:?}", plessor.ops());

    let r = t
        .call(
            &peer,
            "verify_finding",
            json!({"finding_id": needs_a_session}),
        )
        .await;
    assert_eq!(reason(&r), "not_verifiable", "{}", r.text);
    assert!(r.text.contains("it needs auth.cookie"), "{}", r.text);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_proof_that_writes_needs_test_writes_allow_writes_and_a_yes() {
    let plessor = stub_engine(StubOpts::default()).await;
    let deletes = seeded(
        &plessor,
        "http://app.test/",
        template_finding(
            "http://app.test/item/1",
            proof(&[("DELETE", "http://app.test/item/1", json!([]))]),
        ),
    );
    let overridden = seeded(
        &plessor,
        "http://app.test/",
        template_finding(
            "http://app.test/item/1",
            proof(&[(
                "GET",
                "http://app.test/item/1",
                json!([["X-HTTP-Method-Override", "DELETE"]]),
            )]),
        ),
    );
    let t = scope(&["app.test".into()], "")
        .resolver(names())
        .plessor(plessor.port)
        .build();
    let peer = FakePeer::new(Elicit::Accept);
    for id in [&deletes, &overridden] {
        let r = t
            .call(&peer, "verify_finding", json!({"finding_id": id}))
            .await;
        assert_eq!(reason(&r), "invalid_arguments", "{}", r.text);
        assert!(r.text.contains("test_writes"), "{}", r.text);
        let r = t
            .call(
                &peer,
                "verify_finding",
                json!({"finding_id": id, "test_writes": true}),
            )
            .await;
        assert_eq!(reason(&r), "writes_not_allowed", "{}", r.text);
    }
    assert!(plessor.ops().is_empty());

    let t = scope(&["app.test".into()], "allow_writes = true")
        .resolver(names())
        .plessor(plessor.port)
        .build();
    let r = t
        .call(
            &FakePeer::new(Elicit::Decline),
            "verify_finding",
            json!({"finding_id": deletes, "test_writes": true}),
        )
        .await;
    assert_eq!(reason(&r), "declined", "{}", r.text);
    assert!(plessor.ops().is_empty());

    // A no is kept for the life of the server, so the yes is another server's.
    let t = scope(&["app.test".into()], "allow_writes = true")
        .resolver(names())
        .plessor(plessor.port)
        .build();
    let peer = FakePeer::new(Elicit::Accept);
    let r = t
        .call(
            &peer,
            "verify_finding",
            json!({"finding_id": deletes, "test_writes": true}),
        )
        .await;
    ok(&r);
    assert!(
        peer.questions
            .lock()
            .unwrap()
            .iter()
            .any(|q| q.contains("DELETE request")),
        "{:?}",
        peer.questions.lock().unwrap()
    );
    assert_eq!(plessor.ops()[0]["test_writes"], true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_plessor_that_cannot_pin_a_verify_is_not_used() {
    let plessor = stub_engine(StubOpts {
        no_scan_pins: true,
        ..Default::default()
    })
    .await;
    let id = seeded(
        &plessor,
        "http://app.test/",
        template_finding(
            "http://app.test/about",
            proof(&[("GET", "http://app.test/about", json!([]))]),
        ),
    );
    let t = scope(&["app.test".into()], "")
        .resolver(names())
        .plessor(plessor.port)
        .build();
    let r = t
        .call(
            &FakePeer::new(Elicit::None),
            "verify_finding",
            json!({"finding_id": id}),
        )
        .await;
    assert_eq!(reason(&r), "engine_unavailable", "{}", r.text);
    assert!(plessor.ops().is_empty());
}

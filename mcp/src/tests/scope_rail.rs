//! Nothing reaches a destination the scope file does not list.
//!
//! Each traffic tool is pointed at a listener the scope does not name, and the test
//! counts what arrives there and what the engine was asked: both must be zero. The
//! same test then points it at a listener the scope does name and expects traffic,
//! so it cannot pass on a server that has stopped sending anything at all.
//!
//! These scopes set `allow_private = true`. The listeners are on loopback, and
//! without it the address check would refuse them too, which would hide a broken
//! scope check behind a working address check.

use super::support::*;
use serde_json::json;
use std::collections::HashMap;

fn local() -> HashMap<String, std::net::IpAddr> {
    HashMap::new()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fingerprint_sends_nothing_out_of_scope() {
    let inside = listener(Reply::ok("<title>in</title>")).await;
    let outside = listener(Reply::ok("<title>out</title>")).await;
    let toolmark = stub_engine(StubOpts {
        events: toolmark_events("in", "nginx"),
        simulate: Some(local()),
        ..Default::default()
    })
    .await;
    let t = scope(
        &[format!("127.0.0.1:{}", inside.port)],
        "allow_private = true",
    )
    .toolmark(toolmark.port)
    .build();
    let peer = FakePeer::new(Elicit::None);

    let r = t
        .call(
            &peer,
            "fingerprint",
            json!({"url": format!("http://127.0.0.1:{}/", outside.port)}),
        )
        .await;
    assert_eq!(outside.conns(), 0, "the out-of-scope listener was reached");
    assert_eq!(toolmark.ops().len(), 0, "the engine was asked");
    assert_eq!(reason(&r), "out_of_scope");
    assert_eq!(refused_list(&r)[0]["port"], outside.port);

    let r = t
        .call(
            &peer,
            "fingerprint",
            json!({"url": format!("http://127.0.0.1:{}/", inside.port)}),
        )
        .await;
    ok(&r);
    assert_eq!(toolmark.ops().len(), 1);
    assert_eq!(toolmark.ops()[0]["follow_redirects"], false);
    assert!(inside.conns() >= 1, "the positive control sent nothing");
    assert_eq!(outside.conns(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_injection_refuses_the_whole_list_and_names_every_refused_destination() {
    let inside = listener(Reply::ok("ok")).await;
    let outside = listener(Reply::ok("ok")).await;
    let other = listener(Reply::ok("ok")).await;
    let names = FakeResolver::default().with("other.test", &["127.0.0.1"]);
    let mut map = local();
    map.insert("other.test".into(), "127.0.0.1".parse().unwrap());
    let plessor = stub_engine(StubOpts {
        simulate: Some(map),
        ..Default::default()
    })
    .await;
    let t = scope(
        &[format!("127.0.0.1:{}", inside.port)],
        "allow_private = true",
    )
    .plessor(plessor.port)
    .resolver(names)
    .build();
    let peer = FakePeer::new(Elicit::None);

    // One origin, out of scope.
    let r = t
        .call(
            &peer,
            "test_injection",
            json!({"endpoints": [
                {"url": format!("http://127.0.0.1:{}/a?q=1", outside.port)},
                {"url": format!("http://127.0.0.1:{}/b?q=1", outside.port), "method": "POST",
                 "body": [{"name": "q", "value": "1"}]},
            ]}),
        )
        .await;
    assert_eq!(outside.conns(), 0, "the out-of-scope listener was reached");
    assert_eq!(plessor.ops().len(), 0, "the engine was asked");
    assert_eq!(reason(&r), "out_of_scope");

    // A list mixing in and out of scope: refused whole, naming each refused one.
    let r = t
        .call(
            &peer,
            "test_injection",
            json!({"endpoints": [
                {"url": format!("http://127.0.0.1:{}/a?q=1", inside.port)},
                {"url": format!("http://127.0.0.1:{}/b?q=1", outside.port)},
                {"url": format!("http://other.test:{}/c?q=1", other.port)},
            ]}),
        )
        .await;
    assert_eq!(
        (outside.conns(), other.conns()),
        (0, 0),
        "an out-of-scope listener was reached"
    );
    assert_eq!(plessor.ops().len(), 0, "the engine was asked");
    assert_eq!(inside.conns(), 0);
    assert_eq!(reason(&r), "out_of_scope");
    let refused: Vec<u64> = refused_list(&r)
        .iter()
        .map(|x| x["port"].as_u64().unwrap())
        .collect();
    assert!(refused.contains(&(outside.port as u64)) && refused.contains(&(other.port as u64)));
    assert!(!refused.contains(&(inside.port as u64)));

    let r = t
        .call(
            &peer,
            "test_injection",
            json!({"url": format!("http://127.0.0.1:{}/a?q=1", inside.port), "wait_seconds": 5}),
        )
        .await;
    let v = ok(&r);
    assert_eq!(v["status"], "completed", "{v}");
    assert_eq!(plessor.ops().len(), 1);
    let op = &plessor.ops()[0];
    assert_eq!(op["scope"], json!([format!("127.0.0.1:{}", inside.port)]));
    assert!(inside.conns() >= 1, "the positive control sent nothing");
    assert_eq!((outside.conns(), other.conns()), (0, 0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_origins_in_scope_are_two_calls() {
    let a = listener(Reply::ok("ok")).await;
    let b = listener(Reply::ok("ok")).await;
    let plessor = stub_engine(StubOpts::default()).await;
    let t = scope(
        &[
            format!("127.0.0.1:{}", a.port),
            format!("127.0.0.1:{}", b.port),
        ],
        "allow_private = true",
    )
    .plessor(plessor.port)
    .build();
    let r = t
        .call(
            &FakePeer::new(Elicit::None),
            "test_injection",
            json!({"endpoints": [
                {"url": format!("http://127.0.0.1:{}/a?q=1", a.port)},
                {"url": format!("http://127.0.0.1:{}/b?q=1", b.port)},
            ]}),
        )
        .await;
    assert_eq!(reason(&r), "invalid_arguments");
    assert_eq!(plessor.ops().len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_http_request_sends_nothing_out_of_scope() {
    let inside = listener(Reply::ok("in")).await;
    let outside = listener(Reply::ok("out")).await;
    let t = scope(
        &[format!("127.0.0.1:{}", inside.port)],
        "allow_private = true",
    )
    .build();
    let peer = FakePeer::new(Elicit::None);

    let r = t
        .call(
            &peer,
            "send_http_request",
            json!({"method": "GET", "url": format!("http://127.0.0.1:{}/", outside.port)}),
        )
        .await;
    assert_eq!(outside.conns(), 0, "the out-of-scope listener was reached");
    assert_eq!(reason(&r), "out_of_scope");

    let r = t
        .call(
            &peer,
            "send_http_request",
            json!({"method": "GET", "url": format!("http://127.0.0.1:{}/", inside.port)}),
        )
        .await;
    assert_eq!(ok(&r)["status"], 200);
    assert_eq!(inside.conns(), 1);
    assert_eq!(outside.conns(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wildcard_admits_subdomains_only() {
    let inside = listener(Reply::ok("in")).await;
    let outside = listener(Reply::ok("out")).await;
    let names = FakeResolver::default()
        .with("api.example.test", &["127.0.0.1"])
        .with("example.test.evil.test", &["127.0.0.1"])
        .with("example.test", &["127.0.0.1"]);
    let t = scope(&["*.example.test".into()], "allow_private = true")
        .resolver(names)
        .build();
    let peer = FakePeer::new(Elicit::None);

    for host in ["example.test.evil.test", "example.test"] {
        let r = t
            .call(
                &peer,
                "send_http_request",
                json!({"method": "GET", "url": format!("http://{host}:{}/", outside.port)}),
            )
            .await;
        assert_eq!(
            outside.conns(),
            0,
            "{host} reached the out-of-scope listener"
        );
        assert_eq!(reason(&r), "out_of_scope", "{host}");
    }

    let r = t
        .call(
            &peer,
            "send_http_request",
            json!({"method": "GET", "url": format!("http://api.example.test:{}/", inside.port)}),
        )
        .await;
    assert_eq!(ok(&r)["status"], 200);
    assert_eq!(inside.conns(), 1);
    assert!(inside.last_request().contains("api.example.test"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_port_rule_admits_that_port_only() {
    let inside = listener(Reply::ok("in")).await;
    let outside = listener(Reply::ok("out")).await;
    let names = FakeResolver::default().with("api.example.test", &["127.0.0.1"]);
    let t = scope(
        &[format!("api.example.test:{}", inside.port)],
        "allow_private = true",
    )
    .resolver(names)
    .build();
    let peer = FakePeer::new(Elicit::None);
    let r = t
        .call(
            &peer,
            "send_http_request",
            json!({"method": "GET", "url": format!("http://api.example.test:{}/", outside.port)}),
        )
        .await;
    assert_eq!(outside.conns(), 0, "the other port was reached");
    assert_eq!(reason(&r), "out_of_scope");
    let r = t
        .call(
            &peer,
            "send_http_request",
            json!({"method": "GET", "url": format!("http://api.example.test:{}/", inside.port)}),
        )
        .await;
    ok(&r);
    assert_eq!(inside.conns(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn odd_spellings_of_an_address_are_checked_as_the_address() {
    let inside = listener(Reply::ok("in")).await;
    let outside = listener(Reply::ok("out")).await;
    let t = scope(
        &[format!("127.0.0.1:{}", inside.port)],
        "allow_private = true",
    )
    .build();
    let peer = FakePeer::new(Elicit::None);

    let r = t
        .call(
            &peer,
            "send_http_request",
            json!({"method": "GET", "url": format!("http://0x7f.0.0.1:{}/", outside.port)}),
        )
        .await;
    assert_eq!(
        outside.conns(),
        0,
        "0x7f.0.0.1 reached the out-of-scope listener"
    );
    assert_eq!(reason(&r), "out_of_scope");
    assert_eq!(refused_list(&r)[0]["host"], "127.0.0.1");

    let r = t
        .call(
            &peer,
            "send_http_request",
            json!({"method": "GET", "url": "http://in.test@evil.test/"}),
        )
        .await;
    assert_eq!(reason(&r), "invalid_arguments");
    assert_eq!(outside.conns(), 0);

    // The same parse is why a short form of an address in the scope is admitted.
    let r = t
        .call(
            &peer,
            "send_http_request",
            json!({"method": "GET", "url": format!("http://127.1:{}/", inside.port)}),
        )
        .await;
    ok(&r);
    assert_eq!(inside.conns(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_scope_refuses_every_traffic_tool() {
    let target = listener(Reply::ok("x")).await;
    let toolmark = stub_engine(StubOpts {
        events: toolmark_events("t", "s"),
        simulate: Some(local()),
        ..Default::default()
    })
    .await;
    let plessor = stub_engine(StubOpts {
        simulate: Some(local()),
        ..Default::default()
    })
    .await;
    let url = format!("http://127.0.0.1:{}/?q=1", target.port);
    for file in [
        Some("entries = []\nallow_private = true\n".to_string()),
        None,
    ] {
        let t = Build::with_file(file.clone())
            .toolmark(toolmark.port)
            .plessor(plessor.port)
            .build();
        let peer = FakePeer::new(Elicit::Accept);
        for (tool, args) in [
            ("fingerprint", json!({"url": url})),
            ("test_injection", json!({"url": url})),
            ("send_http_request", json!({"method": "GET", "url": url})),
        ] {
            let r = t.call(&peer, tool, args).await;
            assert_eq!(target.conns(), 0, "{tool} with {file:?} reached the target");
            assert_eq!(
                toolmark.ops().len() + plessor.ops().len(),
                0,
                "{tool} asked an engine"
            );
            assert_eq!(reason(&r), "no_scope", "{tool} with {file:?}");
        }
        let s = t.call(&peer, "get_scope", json!({})).await;
        assert!(ok(&s)["how_to"].as_str().unwrap().contains("entries ="));
        assert_eq!(
            peer.asked(),
            0,
            "nobody is asked about a scope that does not exist"
        );
    }
    assert_eq!(toolmark.ops().len() + plessor.ops().len(), 0);
    assert_eq!(target.conns(), 0);
}

#[tokio::test]
async fn check_scope_answers_ranges_and_ports_without_counting_refusals() {
    let t = scope(
        &[
            "10.20.0.0/24".into(),
            "[fd00::1]:8080".into(),
            "fd00:1::/64".into(),
            "app.example.test:8443".into(),
        ],
        "",
    )
    .build();
    let r = t
        .call(
            &FakePeer::new(Elicit::None),
            "check_scope",
            json!({"targets": [
                "10.20.0.255", "10.20.1.0", "10.20.0.0/25", "10.20.0.0/23",
                "[fd00::1]:8080", "[fd00::1]:9090", "fd00:1::5",
                "app.example.test", "https://app.example.test:8443/x", "not a target"
            ]}),
        )
        .await;
    let v = ok(&r);
    let admitted: Vec<bool> = v["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["admitted"].as_bool().unwrap())
        .collect();
    assert_eq!(
        admitted,
        [
            true, false, true, false, true, false, true, false, true, false
        ]
    );
    assert_eq!(v["results"][0]["rule"], "10.20.0.0/24");
    assert_eq!(
        v["results"][7]["port_rules"],
        json!(["app.example.test:8443"])
    );
    assert_eq!(v["results"][9]["kind"], "invalid");
    assert_eq!(
        t.mcp.guard.refused_total(),
        0,
        "a question is not a refusal"
    );
}

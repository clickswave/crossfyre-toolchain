//! doorward's port scan, ambulo's content discovery and voyage's enumeration are fenced
//! as every scan is: by the scope file before anything is sent, and in the engine by the
//! options it confirms it honours, each set from what was cleared.
//!
//! The engines are stubs that record what they are sent and keep what they ran. Names
//! resolve through the test's resolver, and nothing is simulated, so nothing here leaves
//! the machine.

use super::support::*;
use serde_json::{Value, json};

fn names() -> FakeResolver {
    FakeResolver::default()
        .with("app.test", &["93.184.216.34"])
        .with("other.test", &["93.184.216.35"])
}

fn listed(r: &crate::core::ToolResult) -> Vec<Value> {
    ok(r)["scans"].as_array().cloned().unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_port_scan_tries_only_ports_the_scope_admits_and_is_pinned() {
    let doorward = stub_engine(StubOpts {
        events: vec![
            json!({"type": "result", "host": "app.test", "port": 22, "status": "open"}),
            json!({"type": "progress", "processed": 2, "total": 2}),
        ],
        ..Default::default()
    })
    .await;
    let t = scope(&["app.test:22".into(), "app.test:443".into()], "")
        .resolver(names())
        .engine("doorward", doorward.port)
        .build();
    let peer = FakePeer::new(Elicit::None);
    let r = t
        .call(
            &peer,
            "scan_ports",
            json!({"host": "app.test", "ports": [443, 22], "wait_seconds": 5}),
        )
        .await;
    let v = ok(&r).clone();
    assert!(
        v["scan_id"].as_str().unwrap().starts_with("s_doorward_"),
        "{v}"
    );
    assert_eq!(v["counts"]["findings"], 1, "an open port is a finding: {v}");
    assert_eq!(v["progress"]["done"], 2, "{v}");
    let op = &doorward.ops()[0];
    assert_eq!(op["operation"], "scan", "{op}");
    assert_eq!(op["targets"], json!(["app.test"]), "{op}");
    assert_eq!(op["ports"], json!([22, 443]), "{op}");
    assert_eq!(
        op["resolve"],
        json!([["app.test", "93.184.216.34:22"]]),
        "{op}"
    );
    assert_eq!(op["block_internal"], true, "{op}");
    assert_eq!(op["mcp"]["tool"], "scan_ports", "{op}");
    let r = t.call(&peer, "list_scans", json!({})).await;
    assert_eq!(listed(&r)[0]["scan_id"], v["scan_id"], "{}", r.text);

    for ports in [json!([22, 80]), Value::Null] {
        let mut args = json!({"host": "app.test"});
        if !ports.is_null() {
            args["ports"] = ports;
        }
        let r = t.call(&peer, "scan_ports", args).await;
        assert_eq!(reason(&r), "out_of_scope", "{}", r.text);
        assert!(r.text.contains("port"), "{}", r.text);
    }
    assert_eq!(doorward.ops().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn content_discovery_sends_its_words_and_keeps_to_one_origin() {
    let ambulo = stub_engine(StubOpts::default()).await;
    let t = scope(&["app.test".into()], "")
        .resolver(names())
        .engine("ambulo", ambulo.port)
        .build();
    let peer = FakePeer::new(Elicit::None);
    let words = json!(["admin", "backup.zip", "admin"]);
    ok(&t
        .call(
            &peer,
            "discover_content",
            json!({"url": "http://app.test/files", "words": words, "wait_seconds": 5}),
        )
        .await);
    let op = &ambulo.ops()[0];
    assert_eq!(op["endpoint"], "http://app.test/files/::FUZZ::", "{op}");
    assert_eq!(
        op["resolve"],
        json!([["app.test", "93.184.216.34:80"]]),
        "{op}"
    );
    assert_eq!(op["block_internal"], true, "{op}");
    assert_eq!(op["follow_redirects"], false, "{op}");
    assert!(op["wordlist_follows"].is_string(), "{op}");
    assert_eq!(ambulo.kept.lock().unwrap().words, ["admin", "backup.zip"]);

    ok(&t
        .call(
            &peer,
            "discover_content",
            json!({"url": "http://app.test/search?q=::FUZZ::", "words": ["x"]}),
        )
        .await);
    let r = t
        .call(
            &peer,
            "discover_content",
            json!({"url": "http://other.test/::FUZZ::", "words": ["x"]}),
        )
        .await;
    assert_eq!(reason(&r), "out_of_scope", "{}", r.text);
    for (url, words) in [
        ("http://app.test/::FUZZ::/::FUZZ::", json!(["x"])),
        ("http://app.test/::FUZZ::", json!(["has space"])),
        ("http://app.test/::FUZZ::", json!(["http://other.test/"])),
        ("http://app.test/a#::FUZZ::", json!(["x"])),
    ] {
        let r = t
            .call(
                &peer,
                "discover_content",
                json!({"url": url, "words": words}),
            )
            .await;
        assert_eq!(reason(&r), "invalid_arguments", "{url} {words}: {}", r.text);
    }
    assert_eq!(ambulo.ops().len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subdomains_need_the_domain_listed_and_a_wildcard_for_words() {
    let voyage = stub_engine(StubOpts::default()).await;
    let peer = FakePeer::new(Elicit::None);
    let t = scope(&["example.test".into()], "")
        .engine("voyage", voyage.port)
        .build();
    ok(&t
        .call(
            &peer,
            "find_subdomains",
            json!({"domain": "Example.test.", "wait_seconds": 5}),
        )
        .await);
    let op = &voyage.ops()[0];
    assert_eq!(op["operation"], "enum", "{op}");
    assert_eq!(op["domain"], "example.test", "{op}");
    assert_eq!(op["disable_active"], true, "{op}");
    assert_eq!(op["scope"], json!(["example.test"]), "{op}");
    assert_eq!(op["follow_redirects"], false, "{op}");
    assert_eq!(op["block_internal"], true, "{op}");
    assert!(op.get("wordlist_follows").is_none(), "{op}");
    let r = t.call(&peer, "list_scans", json!({})).await;
    assert_eq!(listed(&r).len(), 1, "{}", r.text);
    let r = t
        .call(
            &peer,
            "find_subdomains",
            json!({"domain": "example.test", "words": ["www"]}),
        )
        .await;
    assert_eq!(reason(&r), "out_of_scope", "{}", r.text);
    assert!(r.text.contains("*.example.test"), "{}", r.text);

    let t = scope(&["*.example.test".into()], "")
        .engine("voyage", voyage.port)
        .build();
    ok(&t
        .call(
            &peer,
            "find_subdomains",
            json!({"domain": "example.test", "words": ["www", "api.dev"], "wait_seconds": 5}),
        )
        .await);
    let op = &voyage.ops()[1];
    assert_eq!(op["disable_active"], false, "{op}");
    assert!(op["wordlist_follows"].is_string(), "{op}");
    assert_eq!(voyage.kept.lock().unwrap().words, ["www", "api.dev"]);
    let r = t.call(&peer, "list_scans", json!({})).await;
    assert_eq!(listed(&r).len(), 2, "{}", r.text);
    for args in [
        json!({"domain": "other.test"}),
        json!({"domain": "evil-example.test"}),
    ] {
        let r = t.call(&peer, "find_subdomains", args.clone()).await;
        assert_eq!(reason(&r), "out_of_scope", "{args}: {}", r.text);
    }
    assert_eq!(voyage.ops().len(), 2);
}

/// A port scan of a host the file admits on some ports only is listed only when it tried
/// no other port.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_port_scan_is_listed_only_when_every_port_it_tried_is_in_scope() {
    let doorward = stub_engine(StubOpts::default()).await;
    {
        let mut kept = doorward.kept.lock().unwrap();
        kept.scan("app.test", "completed", json!({"ports": [22]}), &now_utc());
        kept.scan(
            "app.test",
            "completed",
            json!({"ports": [22, 3306]}),
            &now_utc(),
        );
    }
    let t = scope(&["app.test:22".into()], "")
        .engine("doorward", doorward.port)
        .build();
    let r = t
        .call(&FakePeer::new(Elicit::None), "list_scans", json!({}))
        .await;
    assert_eq!(listed(&r).len(), 1, "{}", r.text);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_engine_that_cannot_be_fenced_is_not_used() {
    let old = StubOpts {
        no_scan_pins: true,
        ..Default::default()
    };
    let (doorward, ambulo, voyage) = (
        stub_engine(old.clone()).await,
        stub_engine(old.clone()).await,
        stub_engine(old).await,
    );
    let t = scope(&["app.test".into(), "*.example.test".into()], "")
        .resolver(names())
        .engine("doorward", doorward.port)
        .engine("ambulo", ambulo.port)
        .engine("voyage", voyage.port)
        .build();
    let peer = FakePeer::new(Elicit::None);
    for (tool, args) in [
        ("scan_ports", json!({"host": "app.test", "ports": [22]})),
        (
            "discover_content",
            json!({"url": "http://app.test/::FUZZ::", "words": ["x"]}),
        ),
        ("find_subdomains", json!({"domain": "example.test"})),
    ] {
        let r = t.call(&peer, tool, args).await;
        assert_eq!(reason(&r), "engine_unavailable", "{tool}: {}", r.text);
    }
    assert!(doorward.ops().is_empty() && ambulo.ops().is_empty() && voyage.ops().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engine_scans_count_toward_the_hourly_starts() {
    let doorward = stub_engine(StubOpts::default()).await;
    let t = scope(&["app.test".into()], "max_scan_starts_per_hour = 1")
        .resolver(names())
        .engine("doorward", doorward.port)
        .build();
    let peer = FakePeer::new(Elicit::None);
    let args = json!({"host": "app.test", "ports": [22], "wait_seconds": 5});
    ok(&t.call(&peer, "scan_ports", args.clone()).await);
    let r = t.call(&peer, "scan_ports", args).await;
    assert_eq!(reason(&r), "scan_limit", "{}", r.text);
}

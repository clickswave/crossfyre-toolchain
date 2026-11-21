//! A template scan is fenced as every scan is, and chooses its templates by what toolmark
//! saw on the target; the inventory shows what toolmark saw, in scope only.
//!
//! plessor and toolmark are stubs that record what they are sent and answer as the
//! daemons do. Names resolve through the test's resolver to documentation addresses, and
//! nothing is simulated, so nothing here leaves the machine.

use super::support::*;
use cfx_cve::inventory::NOT_PROOF;
use serde_json::{Value, json};

/// What toolmark keeps of app.test:80, seen now: Apache 2.4.49 and one of its leads, and
/// of other.test:80, which no test's scope file lists.
fn inventory() -> Vec<Value> {
    let row = |host: &str| {
        json!({"host": host, "port": 80, "vendor": "apache", "product": "http_server",
               "version": "2.4.49", "cpe": "cpe:2.3:a:apache:http_server:2.4.49",
               "cpe_names": ["a:apache:http_server"], "distro": "", "last_seen": now_utc(),
               "leads": [{"cve": "CVE-2021-41773", "severity": "critical", "cvss": 7.5,
                          "kev": true, "epss": 0.94, "possible": false, "backport": false}]})
    };
    vec![row("app.test"), row("other.test")]
}

fn names() -> FakeResolver {
    FakeResolver::default()
        .with("app.test", &["93.184.216.34"])
        .with("other.test", &["93.184.216.35"])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_template_scan_is_pinned_and_chosen_by_what_toolmark_saw() {
    let plessor = stub_engine(StubOpts {
        events: vec![json!({"type": "lead_answers", "answers": [
            {"cve": "CVE-2021-41773", "product": "http_server", "answer": "checked, not found",
             "template": "CVE-2021-41773"}]})],
        ..Default::default()
    })
    .await;
    let toolmark = stub_engine(StubOpts::default()).await;
    toolmark.kept.lock().unwrap().inventory = inventory();
    let t = scope(&["app.test".into()], "")
        .resolver(names())
        .plessor(plessor.port)
        .toolmark(toolmark.port)
        .build();
    let peer = FakePeer::new(Elicit::None);
    let r = t
        .call(
            &peer,
            "scan_templates",
            json!({"url": "http://app.test/", "wait_seconds": 5}),
        )
        .await;
    let v = ok(&r).clone();
    assert_eq!(v["status"], "completed", "{v}");
    assert!(
        v["note"]
            .as_str()
            .unwrap()
            .starts_with("the templates were chosen by toolmark's inventory of app.test:80"),
        "{v}"
    );
    let ops = plessor.ops();
    assert_eq!(ops.len(), 1, "{ops:?}");
    let op = &ops[0];
    assert_eq!(op["operation"], "scan", "{op}");
    assert_eq!(op["pack"], true, "{op}");
    assert_eq!(op["follow_redirects"], false, "{op}");
    assert_eq!(
        op["resolve"],
        json!([["app.test", "93.184.216.34:80"]]),
        "{op}"
    );
    assert_eq!(op["block_internal"], true, "{op}");
    assert_eq!(op["test_writes"], false, "{op}");
    assert_eq!(op["products"], json!(["a:apache:http_server"]), "{op}");
    assert_eq!(op["leads"][0]["cve"], "CVE-2021-41773", "{op}");
    assert_eq!(op["mcp"]["tool"], "scan_templates", "{op}");

    // What the scan said of the lead went back to toolmark, under the scan plessor kept.
    let kept_as = v["scan_id"]
        .as_str()
        .unwrap()
        .strip_prefix("s_plessor_")
        .unwrap();
    let back = toolmark.kept.lock().unwrap().lead_answers.clone();
    assert_eq!(back.len(), 1, "{back:?}");
    assert_eq!(back[0]["host"], "app.test");
    assert_eq!(back[0]["port"], 80);
    assert_eq!(back[0]["scan"], kept_as);
    assert_eq!(back[0]["answers"][0]["answer"], "checked, not found");

    let r = t.call(&peer, "list_scans", json!({})).await;
    assert_eq!(ok(&r)["scans"][0]["tool"], "scan_templates", "{}", r.text);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_toolmark_every_template_runs_and_the_scan_says_so() {
    let plessor = stub_engine(StubOpts::default()).await;
    let t = scope(&["app.test".into()], "")
        .resolver(names())
        .plessor(plessor.port)
        .build();
    let r = t
        .call(
            &FakePeer::new(Elicit::None),
            "scan_templates",
            json!({"url": "app.test", "all_templates": true}),
        )
        .await;
    let note = ok(&r)["note"].as_str().unwrap().to_string();
    assert!(
        note.starts_with("toolmark is not answering on port"),
        "{note}"
    );
    assert!(r.text.contains("so every template runs"), "{}", r.text);
    let op = &plessor.ops()[0];
    assert!(
        op.get("products").is_none() && op.get("leads").is_none(),
        "{op}"
    );
    assert_eq!(op["all_templates"], true, "{op}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_template_scan_of_a_host_outside_the_scope_file_is_refused_unsent() {
    let plessor = stub_engine(StubOpts::default()).await;
    let t = scope(&["app.test".into()], "")
        .resolver(names())
        .plessor(plessor.port)
        .build();
    let r = t
        .call(
            &FakePeer::new(Elicit::None),
            "scan_templates",
            json!({"url": "http://other.test/"}),
        )
        .await;
    assert_eq!(reason(&r), "out_of_scope", "{}", r.text);
    assert!(plessor.ops().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_plessor_that_cannot_pin_a_template_scan_is_not_used() {
    let plessor = stub_engine(StubOpts {
        no_scan_pins: true,
        ..Default::default()
    })
    .await;
    let t = scope(&["app.test".into()], "")
        .resolver(names())
        .plessor(plessor.port)
        .build();
    let r = t
        .call(
            &FakePeer::new(Elicit::None),
            "scan_templates",
            json!({"url": "http://app.test/"}),
        )
        .await;
    assert_eq!(reason(&r), "engine_unavailable", "{}", r.text);
    assert!(plessor.ops().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn templates_that_write_need_allow_writes_and_a_yes() {
    let plessor = stub_engine(StubOpts::default()).await;
    let args = json!({"url": "http://app.test/", "test_writes": true});
    let t = scope(&["app.test".into()], "")
        .resolver(names())
        .plessor(plessor.port)
        .build();
    let r = t
        .call(
            &FakePeer::new(Elicit::Accept),
            "scan_templates",
            args.clone(),
        )
        .await;
    assert_eq!(reason(&r), "writes_not_allowed", "{}", r.text);

    let t = scope(&["app.test".into()], "allow_writes = true")
        .resolver(names())
        .plessor(plessor.port)
        .build();
    let r = t
        .call(&FakePeer::new(Elicit::None), "scan_templates", args.clone())
        .await;
    assert_eq!(reason(&r), "not_confirmed", "{}", r.text);
    assert!(plessor.ops().is_empty());

    let peer = FakePeer::new(Elicit::Accept);
    ok(&t.call(&peer, "scan_templates", args).await);
    assert!(
        peer.questions
            .lock()
            .unwrap()
            .iter()
            .any(|q| q.contains("PUT, PATCH and DELETE")),
        "{:?}",
        peer.questions.lock().unwrap()
    );
    assert_eq!(plessor.ops()[0]["test_writes"], true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn template_scans_count_toward_the_hourly_starts() {
    let plessor = stub_engine(StubOpts::default()).await;
    let t = scope(&["app.test".into()], "max_scan_starts_per_hour = 1")
        .resolver(names())
        .plessor(plessor.port)
        .build();
    let peer = FakePeer::new(Elicit::None);
    let args = json!({"url": "http://app.test/", "wait_seconds": 5});
    ok(&t.call(&peer, "scan_templates", args.clone()).await);
    let r = t.call(&peer, "scan_templates", args).await;
    assert_eq!(reason(&r), "scan_limit", "{}", r.text);
    assert_eq!(plessor.ops().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_inventory_shows_the_hosts_in_scope_and_the_answers_to_their_leads() {
    let toolmark = stub_engine(StubOpts::default()).await;
    let mut rows = inventory();
    rows[0]["leads"][0]["answer"] = json!("checked, not found");
    rows[0]["leads"][0]["answer_template"] = json!("CVE-2021-41773");
    rows[0]["leads"][0]["answer_scan"] = json!("4f2a7c1e-0b6d-4d3e-9a51-7c2e8f1b3a90");
    toolmark.kept.lock().unwrap().inventory = rows;
    let t = scope(&["app.test".into()], "")
        .resolver(names())
        .toolmark(toolmark.port)
        .build();
    let peer = FakePeer::new(Elicit::None);
    let r = t.call(&peer, "get_inventory", json!({})).await;
    let v = ok(&r).clone();
    assert_eq!(v["target_data"]["untrusted"], true, "{v}");
    let shown = v["target_data"]["inventory"].as_array().unwrap();
    assert_eq!(shown.len(), 1, "only app.test is in scope: {v}");
    assert_eq!(shown[0]["host"], "app.test");
    assert_eq!(shown[0]["version"], "2.4.49");
    let lead = &shown[0]["cve_leads"][0];
    assert_eq!(lead["cve"], "CVE-2021-41773");
    assert_eq!(lead["answer"], "checked, not found");
    assert_eq!(lead["not_proof"], NOT_PROOF);
    assert_eq!(
        lead["answer_scan"],
        "s_plessor_4f2a7c1e-0b6d-4d3e-9a51-7c2e8f1b3a90"
    );
    assert_eq!(v["note"], NOT_PROOF);

    let r = t
        .call(&peer, "get_inventory", json!({"host": "other.test"}))
        .await;
    assert_eq!(ok(&r)["target_data"]["inventory"], json!([]), "{}", r.text);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_inventory_needs_toolmark_running() {
    let t = scope(&["app.test".into()], "").build();
    let r = t
        .call(&FakePeer::new(Elicit::None), "get_inventory", json!({}))
        .await;
    assert_eq!(reason(&r), "engine_unavailable", "{}", r.text);
}

//! The Cloud launch tools: held to the scope file before anything is sent, confirmed
//! once, carrying only what their type allows, and followed while they run.

use super::fake_cloud::{self, KEY, Resp, World, cid, uuid};
use super::support::*;
use crate::cloud::Listing;
use cfx_cloud_wire::{self as wire, IdKind};
use serde_json::json;

fn starts(cloud: &fake_cloud::FakeCloud) -> Vec<fake_cloud::Req> {
    cloud
        .requests()
        .into_iter()
        .filter(|r| r.route == "scans/start")
        .collect()
}

#[tokio::test]
async fn a_launch_outside_the_scope_file_sends_nothing() {
    // The workspace confirmed app.example.com and *.example.org for the key; the scope
    // file lists app.example.com alone.
    let (t, cloud, world) = fake_cloud::server(&["app.example.com"], World::new("launch")).await;
    let peer = FakePeer::new(Elicit::Accept);
    let before = cloud.requests().len();
    for (tool, args) in [
        (
            "start_vuln_scan",
            json!({"urls": ["https://www.example.org/"]}),
        ),
        (
            "start_vuln_scan",
            json!({"urls": ["https://app.example.com/", "https://evil.example/"]}),
        ),
        ("start_crawl", json!({"url": "https://api.example.com/"})),
        ("start_recon", json!({"domain": "example.org"})),
        ("start_port_scan", json!({"targets": ["10.9.0.0/24"]})),
    ] {
        let r = t.call(&peer, tool, args.clone()).await;
        assert_eq!(
            reason(&r),
            "out_of_local_scope",
            "{tool} {args}: {}",
            r.text
        );
        assert!(!refused_list(&r).is_empty(), "{}", r.text);
    }
    // Not a request of any kind, not even the scope list for the confirmation.
    assert_eq!(cloud.requests().len(), before, "{:?}", cloud.routes());
    assert_eq!(peer.asked(), 0);
    assert!(world.lock().unwrap().started.is_empty());
    let r = t
        .call(
            &peer,
            "start_vuln_scan",
            json!({"urls": ["https://app.example.com/", "https://evil.example/"]}),
        )
        .await;
    let refused = refused_list(&r);
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0]["host"], "evil.example");
    assert_eq!(refused[0]["at"], "local_scope");
    let line = t.audit_lines().pop().unwrap();
    assert_eq!(line["reason"], "out_of_local_scope");
    assert_eq!(line["backend"], "local");

    // In both: sent, and started.
    let r = t
        .call(
            &peer,
            "start_vuln_scan",
            json!({"urls": ["https://app.example.com/"]}),
        )
        .await;
    let v = ok(&r);
    assert_eq!(v["backend"], "cloud");
    assert!(v["scan_id"].as_str().unwrap().starts_with("cs_"));
    assert_eq!(starts(&cloud).len(), 1);
}

#[tokio::test]
async fn an_empty_scope_file_narrows_nothing_and_the_platform_decides() {
    let (t, cloud, world) = fake_cloud::server(&[], World::new("launch")).await;
    let peer = FakePeer::new(Elicit::None);
    // Confirmed for the key: started.
    let v = ok(&t
        .call(
            &peer,
            "start_recon",
            json!({"domain": "staging.example.org", "mode": "active"}),
        )
        .await)
    .clone();
    assert_eq!(v["status"], "running");
    assert_eq!(v["poll_after_seconds"], 10);
    // Not confirmed for the key: the platform refuses, naming the target.
    let r = t
        .call(
            &peer,
            "start_port_scan",
            json!({"targets": ["10.9.0.5", "app.example.com"]}),
        )
        .await;
    assert_eq!(reason(&r), "out_of_scope", "{}", r.text);
    let refused = refused_list(&r);
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0]["host"], "10.9.0.5");
    assert_eq!(refused[0]["at"], "cloud_scope");
    assert_eq!(world.lock().unwrap().started.len(), 1);
    // An empty workspace scope, and one with nothing confirmed for the key.
    world
        .lock()
        .unwrap()
        .scope
        .iter_mut()
        .for_each(|e| e.1 = false);
    let r = t
        .call(
            &peer,
            "start_crawl",
            json!({"url": "https://app.example.com/"}),
        )
        .await;
    assert_eq!(reason(&r), "scope_not_attested", "{}", r.text);
    world.lock().unwrap().scope.clear();
    let r = t
        .call(
            &peer,
            "start_crawl",
            json!({"url": "https://app.example.com/"}),
        )
        .await;
    assert_eq!(reason(&r), "scope_empty", "{}", r.text);
    assert_eq!(starts(&cloud).len(), 4);
}

#[tokio::test]
async fn each_launch_carries_its_targets_and_only_its_own_options() {
    let mut w = World::new("launch");
    w.scope.push(("10.9.0.0/24".into(), true));
    let (t, cloud, world) = fake_cloud::server(&[], w).await;
    let peer = FakePeer::new(Elicit::None);
    let node = cid(IdKind::Node, 901);
    let cases = [
        (
            "start_recon",
            json!({"domain": "example.org", "node_ids": [node]}),
            json!({"type": "recon", "targets": ["example.org"], "node_ids": [uuid(901)],
                   "options": {}}),
        ),
        (
            "start_port_scan",
            json!({"targets": ["10.9.0.0/25", "10.9.0.7"], "ports": "22,80,8000-8100"}),
            json!({"type": "port_scan", "targets": ["10.9.0.0/25", "10.9.0.7"], "node_ids": [],
                   "options": {"ports": "22,80,8000-8100"}}),
        ),
        (
            "start_crawl",
            json!({"url": "https://app.example.com/", "max_depth": 2, "max_pages": 50}),
            json!({"type": "crawl", "targets": ["https://app.example.com/"], "node_ids": [],
                   "options": {"max_depth": 2, "max_pages": 50}}),
        ),
        (
            "start_content_discovery",
            json!({"url": "https://app.example.com/", "wordlist": "common",
                   "extensions": ["php"], "recurse": true}),
            json!({"type": "content_discovery", "targets": ["https://app.example.com/"],
                   "node_ids": [], "options": {"wordlist": "common", "extensions": ["php"],
                   "recurse": true}}),
        ),
        (
            "start_vuln_scan",
            json!({"urls": ["https://app.example.com/a", "https://app.example.com/b"],
                   "severity_min": "high", "tags": ["cve"]}),
            json!({"type": "vuln_scan",
                   "targets": ["https://app.example.com/a", "https://app.example.com/b"],
                   "node_ids": [], "options": {"severity_min": "high", "tags": ["cve"]}}),
        ),
        (
            "start_authz_scan",
            json!({"url": "https://app.example.com/", "identities": ["admin", "viewer"]}),
            json!({"type": "authz_scan", "targets": ["https://app.example.com/"],
                   "node_ids": [], "options": {"identities": ["admin", "viewer"]}}),
        ),
    ];
    let mut ids = std::collections::HashSet::new();
    for (tool, args, want) in cases {
        let r = t.call(&peer, tool, args).await;
        ok(&r);
        // Each ends before the next, as a key may have only five running.
        fake_cloud::end_scans(&world);
        let sent = starts(&cloud).pop().unwrap();
        let mut body = sent.body.clone();
        let rid = body.as_object_mut().unwrap().remove("request_id").unwrap();
        assert!(rid.as_str().unwrap().starts_with("r_"), "{rid}");
        assert!(ids.insert(rid), "a request_id was reused");
        assert_eq!(body, want, "{tool}");
        assert_eq!(sent.header(wire::header::TOOL), Some(tool));
        assert_eq!(sent.raw.matches(&KEY[4..]).count(), 1);
    }
    // No schema takes anything else, and the wrong type's option is refused before
    // anything is sent.
    let n = starts(&cloud).len();
    for (tool, args) in [
        (
            "start_crawl",
            json!({"url": "https://app.example.com/", "follow_external": true}),
        ),
        (
            "start_crawl",
            json!({"url": "https://app.example.com/", "max_depth": 11}),
        ),
        (
            "start_port_scan",
            json!({"targets": ["app.example.com"], "ports": "1-2001"}),
        ),
        (
            "start_port_scan",
            json!({"targets": ["app.example.com:443"]}),
        ),
        ("start_vuln_scan", json!({"urls": []})),
        (
            "start_vuln_scan",
            json!({"urls": vec!["https://app.example.com/"; 21]}),
        ),
        ("start_vuln_scan", json!({"urls": ["app.example.com"]})),
        (
            "start_authz_scan",
            json!({"url": "https://app.example.com/", "identities": []}),
        ),
        (
            "start_recon",
            json!({"domain": "example.org", "node_ids": ["n1"]}),
        ),
        ("start_recon", json!({"domain": "10.0.0.1"})),
        (
            "start_recon",
            json!({"domain": "example.org", "wait_seconds": 51}),
        ),
    ] {
        let r = t.call(&peer, tool, args.clone()).await;
        assert_eq!(reason(&r), "invalid_arguments", "{tool} {args}: {}", r.text);
    }
    assert_eq!(starts(&cloud).len(), n);
}

#[tokio::test]
async fn a_read_key_lists_no_launch_and_sends_none() {
    let (t, cloud, _) = fake_cloud::server(&[], World::new("read")).await;
    assert_eq!(t.mcp.backends().cloud, Some(Listing::Read));
    let peer = FakePeer::new(Elicit::Accept);
    let r = t
        .call(
            &peer,
            "start_crawl",
            json!({"url": "https://app.example.com/"}),
        )
        .await;
    assert_eq!(reason(&r), "permission_denied", "{}", r.text);
    assert!(starts(&cloud).is_empty());
    assert_eq!(peer.asked(), 0);

    let (t, _, _) = fake_cloud::server(&[], World::new("launch")).await;
    let listed: Vec<String> = crate::server::tool_list(&t.mcp.backends())
        .into_iter()
        .map(|t| t.name.to_string())
        .collect();
    assert_eq!(listed.len(), 21);
    assert_eq!(listed[15..], crate::cloud::LAUNCH_NAMES);
}

#[tokio::test]
async fn the_person_confirms_once_and_a_no_holds() {
    let (t, cloud, _) = fake_cloud::server(&[], World::new("launch")).await;
    let yes = FakePeer::new(Elicit::Accept);
    let crawl = json!({"url": "https://app.example.com/"});
    ok(&t.call(&yes, "start_crawl", crawl.clone()).await);
    ok(&t.call(&yes, "start_crawl", crawl.clone()).await);
    assert_eq!(yes.asked(), 1);
    let q = yes.questions.lock().unwrap()[0].clone();
    assert!(q.contains("Acme staging"), "{q}");
    assert!(q.contains("app.example.com, *.example.org"), "{q}");
    let line = t.audit_lines().pop().unwrap();
    assert_eq!(line["confirmation"], "form");
    assert!(line["scan_id"].as_str().unwrap().starts_with("cs_"));

    let (t, cloud2, _) = fake_cloud::server(&[], World::new("launch")).await;
    let no = FakePeer::new(Elicit::Decline);
    let r = t.call(&no, "start_crawl", crawl.clone()).await;
    assert_eq!(reason(&r), "declined");
    let r = t.call(&no, "start_crawl", crawl.clone()).await;
    assert_eq!(reason(&r), "declined");
    assert_eq!(no.asked(), 1);
    assert!(starts(&cloud2).is_empty());

    // A client with no form: the key's own attestation, and the audit says so.
    let (t, _, _) = fake_cloud::server(&[], World::new("launch")).await;
    let none = FakePeer::new(Elicit::None);
    ok(&t.call(&none, "start_crawl", crawl).await);
    assert_eq!(
        t.audit_lines().pop().unwrap()["confirmation"],
        "key_attestation"
    );
    assert_eq!(starts(&cloud).len(), 2);
}

#[tokio::test]
async fn a_launch_is_followed_while_it_runs() {
    let mut w = World::new("launch");
    w.advance = 3;
    let (t, _, _) = fake_cloud::server(&[], w).await;
    let peer = FakePeer::new(Elicit::None);
    let v = ok(&t
        .call(
            &peer,
            "start_vuln_scan",
            json!({"urls": ["https://app.example.com/"], "wait_seconds": 5}),
        )
        .await)
    .clone();
    assert_eq!(v["status"], "completed");
    assert_eq!(v["poll_after_seconds"], 0);
    let p = peer.progress.lock().unwrap().clone();
    assert_eq!(
        p,
        vec![
            (3.0, Some(10.0)),
            (6.0, Some(10.0)),
            (9.0, Some(10.0)),
            (10.0, Some(10.0))
        ]
    );
    let m = peer.progress_messages.lock().unwrap().clone();
    assert!(m[0].contains("probing"), "{m:?}");

    // Cancelled while it waits: the call ends, the scan goes on.
    let mut w = World::new("launch");
    w.advance = 0;
    let (t, _, world) = fake_cloud::server(&[], w).await;
    let ct = tokio_util::sync::CancellationToken::new();
    let c2 = ct.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        c2.cancel();
    });
    let r = t
        .call_ct(
            &peer,
            "start_crawl",
            json!({"url": "https://app.example.com/", "wait_seconds": 30}),
            ct,
        )
        .await;
    assert_eq!(reason(&r), "cancelled", "{}", r.text);
    assert_eq!(world.lock().unwrap().scans[0]["status"], "running");
}

#[tokio::test]
async fn a_retried_launch_starts_one_scan() {
    let mut w = World::new("launch");
    w.queue("scans/start", Resp::hangup());
    let (t, cloud, world) = fake_cloud::server(&[], w).await;
    let peer = FakePeer::new(Elicit::None);
    let v = ok(&t
        .call(
            &peer,
            "start_crawl",
            json!({"url": "https://app.example.com/"}),
        )
        .await)
    .clone();
    assert!(v["scan_id"].as_str().unwrap().starts_with("cs_"));
    let sent = starts(&cloud);
    assert_eq!(sent.len(), 2, "one dropped, one retried");
    assert_eq!(sent[0].body["request_id"], sent[1].body["request_id"]);
    assert_eq!(world.lock().unwrap().started.len(), 1);
    let line = t.audit_lines().pop().unwrap();
    assert_eq!(line["decision"], "ok");
}

#[tokio::test]
async fn the_platforms_refusals_of_a_launch_say_what_to_do() {
    let mut w = World::new("launch");
    w.queue(
        "scans/start",
        Resp::with(
            402,
            json!({"reason": "plan_feature", "feature": "authz_engine"}),
        ),
    );
    w.queue(
        "scans/start",
        Resp::with(
            400,
            json!({"reason": "node_unavailable", "nodes": [uuid(902)]}),
        ),
    );
    w.queue("scans/start", Resp::refusal(429, wire::Reason::ScanLimit));
    w.queue(
        "scans/start",
        Resp::refusal(403, wire::Reason::ApprovalRequired),
    );
    let (t, _, _) = fake_cloud::server(&[], w).await;
    let peer = FakePeer::new(Elicit::None);
    let authz = json!({"url": "https://app.example.com/", "identities": ["admin"]});
    let r = t.call(&peer, "start_authz_scan", authz.clone()).await;
    assert_eq!(reason(&r), "plan_feature");
    assert!(
        r.text.contains("\"feature\":\"authz_engine\""),
        "{}",
        r.text
    );
    let r = t.call(&peer, "start_authz_scan", authz.clone()).await;
    assert_eq!(reason(&r), "node_unavailable");
    assert!(r.text.contains(&cid(IdKind::Node, 902)), "{}", r.text);
    let r = t.call(&peer, "start_authz_scan", authz.clone()).await;
    assert_eq!(reason(&r), "scan_limit");
    let r = t.call(&peer, "start_authz_scan", authz).await;
    assert_eq!(reason(&r), "approval_required");
    assert!(r.text.contains("Register a phone"), "{}", r.text);
}

#[tokio::test]
async fn a_launch_the_platform_made_keeps_its_handle_when_a_later_request_fails() {
    // Started, then one read of it fails while the call follows it.
    let mut w = World::new("launch");
    w.queue("scans/get", Resp::refusal(500, wire::Reason::Internal));
    let (t, _, world) = fake_cloud::server(&[], w).await;
    let peer = FakePeer::new(Elicit::None);
    let follow = json!({"url": "https://app.example.com/", "wait_seconds": 5});
    let r = t.call(&peer, "start_crawl", follow.clone()).await;
    let v = ok(&r).clone();
    assert!(v["scan_id"].as_str().unwrap().starts_with("cs_"), "{v}");
    assert_eq!(v["status"], "running");
    assert!(v["poll_after_seconds"].as_u64().unwrap() > 0, "{v}");
    assert!(
        v["cloud_error"]
            .as_str()
            .unwrap()
            .contains("cloud_unavailable")
    );
    assert!(
        !r.text.contains("nothing was read or started"),
        "{}",
        r.text
    );
    assert!(r.text.contains("get_scan"), "{}", r.text);
    assert_eq!(world.lock().unwrap().started.len(), 1);
    let line = t.audit_lines().pop().unwrap();
    assert_eq!(line["decision"], "ok", "{line}");
    assert_eq!(line["scan_id"], v["scan_id"]);
    assert_eq!(line["result"]["cloud_error"], v["cloud_error"]);

    // Rate limited while following: the handle, and not asked again before the limit.
    let mut w = World::new("launch");
    w.rate_limit_after = Some(2);
    let (t, _, _) = fake_cloud::server(&[], w).await;
    let v = ok(&t.call(&peer, "start_crawl", follow).await).clone();
    assert!(v["scan_id"].as_str().unwrap().starts_with("cs_"), "{v}");
    assert!(v["cloud_error"].as_str().unwrap().contains("rate_limited"));
    assert_eq!(v["poll_after_seconds"], 60);

    // Held for a person, and the wait for the decision fails: the ap_ handle.
    let mut w = World::new("launch");
    w.policy = "always";
    w.phones = vec!["Pixel 8"];
    w.queue("approvals/wait", Resp::refusal(500, wire::Reason::Internal));
    let (t, _, world) = fake_cloud::server(&[], w).await;
    let urls = json!({"urls": ["https://app.example.com/"]});
    let r = t.call(&peer, "start_vuln_scan", urls.clone()).await;
    let v = ok(&r).clone();
    assert!(v["scan_id"].as_str().unwrap().starts_with("ap_"), "{v}");
    assert_eq!(v["status"], "awaiting_approval");
    assert!(v["cloud_error"].is_string(), "{v}");
    assert!(
        !r.text.contains("nothing was read or started"),
        "{}",
        r.text
    );
    let pending = |w: &World| w.approvals.values().all(|a| a["status"] == "pending");
    assert!(pending(&world.lock().unwrap()));

    // The person answers in the form and the decision cannot be sent.
    let mut w = World::new("launch");
    w.policy = "always";
    w.queue(
        "approvals/decide",
        Resp::refusal(500, wire::Reason::Internal),
    );
    let (t, _, _) = fake_cloud::server(&[], w).await;
    let yes = FakePeer::new(Elicit::Accept);
    let v = ok(&t.call(&yes, "start_vuln_scan", urls.clone()).await).clone();
    assert!(v["scan_id"].as_str().unwrap().starts_with("ap_"), "{v}");
    assert_eq!(v["status"], "awaiting_approval");
    assert!(v["cloud_error"].is_string(), "{v}");

    // Approved and launched, and the scan it became cannot be read just now.
    let mut w = World::new("launch");
    w.policy = "always";
    w.phones = vec!["Pixel 8"];
    w.decide_on_wait = Some((1, "approved", "phone"));
    w.queue("scans/get", Resp::refusal(500, wire::Reason::Internal));
    let (t, _, _) = fake_cloud::server(&[], w).await;
    let v = ok(&t.call(&peer, "start_vuln_scan", urls.clone()).await).clone();
    assert!(v["scan_id"].as_str().unwrap().starts_with("ap_"), "{v}");
    assert_eq!(v["status"], "launching");
    assert!(
        v["approval"]["scan_id"]
            .as_str()
            .unwrap()
            .starts_with("cs_"),
        "{v}"
    );
    assert!(v["cloud_error"].is_string(), "{v}");

    // No answer to either try of scans/start: it may have been made.
    let mut w = World::new("launch");
    w.queue("scans/start", Resp::hangup());
    w.queue("scans/start", Resp::hangup());
    let (t, _, _) = fake_cloud::server(&[], w).await;
    let r = t.call(&peer, "start_vuln_scan", urls).await;
    assert_eq!(reason(&r), "cloud_unavailable", "{}", r.text);
    assert!(r.text.contains("may have been made"), "{}", r.text);
    assert!(r.text.contains("list_scans"), "{}", r.text);
    assert!(
        !r.text.contains("nothing was read or started"),
        "{}",
        r.text
    );
}

#[tokio::test]
async fn a_launch_key_whose_owner_may_no_longer_launch_loses_its_launch_tools() {
    let (t, cloud, world) = fake_cloud::server(&[], World::new("launch")).await;
    assert_eq!(t.mcp.backends().cloud, Some(Listing::Launch));
    let peer = FakePeer::new(Elicit::None);
    // Demoted in the workspace since the server started.
    world.lock().unwrap().role_may_launch = false;
    let r = t
        .call(
            &peer,
            "start_crawl",
            json!({"url": "https://app.example.com/"}),
        )
        .await;
    assert_eq!(reason(&r), "permission_denied", "{}", r.text);
    assert!(r.text.contains("role"), "{}", r.text);
    assert!(r.text.contains("Viewer"), "{}", r.text);
    // What the platform says the key may do now decides the list, and the client is told.
    assert_eq!(t.mcp.backends().cloud, Some(Listing::Read));
    assert_eq!(
        peer.list_changed.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        cloud.routes().iter().filter(|r| *r == "whoami").count(),
        2,
        "{:?}",
        cloud.routes()
    );
    let line = t.audit_lines().pop().unwrap();
    assert_eq!(line["cloud_call_ids"].as_array().map(Vec::len), Some(2));
    assert!(world.lock().unwrap().scans.is_empty());
}

#[tokio::test]
async fn the_platform_checks_the_launch_before_it_makes_anything() {
    let (t, cloud, world) = fake_cloud::server(&[], World::new("launch")).await;
    let peer = FakePeer::new(Elicit::None);
    let crawl = |node: Option<u32>| {
        let mut a = json!({"url": "https://app.example.com/"});
        if let Some(n) = node {
            a["node_ids"] = json!([cid(IdKind::Node, n)]);
        }
        a
    };
    // A node that is offline, and one the workspace does not have.
    for n in [902, 999] {
        let r = t.call(&peer, "start_crawl", crawl(Some(n))).await;
        assert_eq!(reason(&r), "node_unavailable", "{}", r.text);
        assert!(r.text.contains(&cid(IdKind::Node, n)), "{}", r.text);
    }
    // Out of scope is refused before the nodes are looked at.
    world.lock().unwrap().nodes[0]["status"] = json!("offline");
    let r = t
        .call(
            &peer,
            "start_crawl",
            json!({"url": "https://elsewhere.example/"}),
        )
        .await;
    assert_eq!(reason(&r), "out_of_scope", "{}", r.text);
    assert_eq!(refused_list(&r)[0]["host"], "elsewhere.example");
    let r = t.call(&peer, "start_crawl", crawl(None)).await;
    assert_eq!(reason(&r), "no_online_node", "{}", r.text);
    world.lock().unwrap().nodes[0]["status"] = json!("online");
    // A wordlist or a role the workspace does not have.
    let r = t
        .call(
            &peer,
            "start_content_discovery",
            json!({"url": "https://app.example.com/", "wordlist": "nosuch"}),
        )
        .await;
    assert_eq!(reason(&r), "invalid_arguments", "{}", r.text);
    assert!(r.text.contains("nosuch"), "{}", r.text);
    let r = t
        .call(
            &peer,
            "start_authz_scan",
            json!({"url": "https://app.example.com/", "identities": ["auditor"]}),
        )
        .await;
    assert_eq!(reason(&r), "invalid_arguments", "{}", r.text);
    assert!(world.lock().unwrap().scans.is_empty());
    assert_eq!(starts(&cloud).len(), 6);

    // Five running is the most one key may have.
    let (t, cloud, world) = fake_cloud::server(&[], World::new("launch")).await;
    for _ in 0..5 {
        ok(&t.call(&peer, "start_crawl", crawl(None)).await);
    }
    for _ in 0..5 {
        let r = t.call(&peer, "start_crawl", crawl(None)).await;
        assert_eq!(reason(&r), "scan_limit", "{}", r.text);
    }
    // Ten launches an hour, refused ones included, and the wait is the hour's rest.
    let r = t.call(&peer, "start_crawl", crawl(None)).await;
    assert_eq!(reason(&r), "rate_limited", "{}", r.text);
    let wait = r
        .text
        .split("\"retry_after_seconds\":")
        .nth(1)
        .and_then(|s| s.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap();
    assert!(wait > 3500 && wait <= 3600, "{wait}");
    assert_eq!(world.lock().unwrap().scans.len(), 5);
    assert_eq!(starts(&cloud).len(), 11);
}

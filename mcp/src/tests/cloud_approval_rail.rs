//! A launch the workspace holds for a person: the call waits on the owner's phone when
//! there is one, asks in the agent's client only when there is none and the workspace
//! allows it, and otherwise hands back where the launch can be decided.

use super::fake_cloud::{self, World};
use super::support::*;
use crate::cloud::Listing;
use serde_json::{Value, json};

fn held(policy: &'static str, phones: Vec<&'static str>, fallback: bool) -> World {
    let mut w = World::new("launch");
    w.policy = policy;
    w.phones = phones;
    w.fallback = fallback;
    w
}

fn decides(cloud: &fake_cloud::FakeCloud) -> Vec<Value> {
    cloud
        .requests()
        .into_iter()
        .filter(|r| r.route == "approvals/decide")
        .map(|r| r.body)
        .collect()
}

const SCAN: &str = "start_vuln_scan";

fn args() -> Value {
    json!({"urls": ["https://app.example.com/"]})
}

#[tokio::test]
async fn with_a_phone_the_call_waits_on_the_phone_alone() {
    let mut w = held("always", vec!["Pixel 8"], true);
    w.decide_on_wait = Some((2, "approved", "phone"));
    let (t, cloud, _) = fake_cloud::server(&[], w).await;
    // A client that would say yes to anything is not asked to approve.
    let peer = FakePeer::new(Elicit::Accept);
    let v = ok(&t.call(&peer, SCAN, args()).await).clone();
    assert!(v["scan_id"].as_str().unwrap().starts_with("cs_"), "{v}");
    assert_eq!(v["status"], "running");
    assert_eq!(v["approval"]["decided_via"], "phone");
    assert_eq!(
        peer.asked(),
        0,
        "the policy asks every launch, so no form either"
    );
    assert!(decides(&cloud).is_empty());
    let msgs = peer.progress_messages.lock().unwrap().clone();
    assert!(
        msgs.iter().all(|m| m == "Waiting for approval on Pixel 8"),
        "{msgs:?}"
    );
    assert!(!msgs.is_empty());
    let line = t.audit_lines().pop().unwrap();
    assert_eq!(line["confirmation"], "approval:phone");
    assert!(line["approval_id"].as_str().unwrap().starts_with("ap_"));
    assert!(line["scan_id"].as_str().unwrap().starts_with("ap_"));

    // Nobody decides in time: the handle and the page.
    let (t, cloud, _) = fake_cloud::server(&[], held("always", vec!["Pixel 8"], true)).await;
    let v = ok(&t.call(&peer, SCAN, args()).await).clone();
    assert_eq!(v["status"], "awaiting_approval");
    assert!(v["scan_id"].as_str().unwrap().starts_with("ap_"));
    assert_eq!(v["poll_after_seconds"], 15);
    let page = v["approval"]["approve_url"].as_str().unwrap();
    assert!(page.starts_with(&cloud.url()), "{page}");
    assert!(decides(&cloud).is_empty());
    // And get_scan reads it later.
    let id = v["scan_id"].clone();
    let g = ok(&t.call(&peer, "get_scan", json!({"scan_id": id})).await).clone();
    assert_eq!(g["status"], "awaiting_approval");
}

#[tokio::test]
async fn with_no_phone_a_client_that_opens_urls_is_sent_to_the_page() {
    let mut w = held("always", vec![], true);
    w.decide_on_wait = Some((1, "approved", "dashboard"));
    let (t, cloud, _) = fake_cloud::server(&[], w).await;
    let mut peer = FakePeer::new(Elicit::Accept);
    peer.url = Elicit::Accept;
    let v = ok(&t.call(&peer, SCAN, args()).await).clone();
    assert!(v["scan_id"].as_str().unwrap().starts_with("cs_"), "{v}");
    let urls = peer.urls.lock().unwrap().clone();
    assert_eq!(urls.len(), 1);
    assert!(
        urls[0].starts_with(&format!("{}/m/approve/", cloud.url())),
        "{urls:?}"
    );
    // The browser decided, not the form.
    assert_eq!(peer.asked(), 0);
    assert!(decides(&cloud).is_empty());
    assert_eq!(
        t.audit_lines().pop().unwrap()["confirmation"],
        "approval:dashboard"
    );

    // Declined to open it: nothing is decided, the handle comes back.
    let (t, cloud, _) = fake_cloud::server(&[], held("always", vec![], true)).await;
    let mut peer = FakePeer::new(Elicit::None);
    peer.url = Elicit::Decline;
    let v = ok(&t.call(&peer, SCAN, args()).await).clone();
    assert_eq!(v["status"], "awaiting_approval");
    assert!(decides(&cloud).is_empty());
}

#[tokio::test]
async fn with_no_phone_a_form_decides_and_both_answers_reach_the_platform() {
    let (t, cloud, _) = fake_cloud::server(&[], held("always", vec![], true)).await;
    let yes = FakePeer::new(Elicit::Accept);
    let v = ok(&t.call(&yes, SCAN, args()).await).clone();
    assert!(v["scan_id"].as_str().unwrap().starts_with("cs_"), "{v}");
    assert_eq!(yes.asked(), 1);
    let q = yes.questions.lock().unwrap()[0].clone();
    assert!(
        q.contains("vuln_scan") && q.contains("https://app.example.com/"),
        "{q}"
    );
    assert!(q.contains("1 node(s) of Acme staging"), "{q}");
    let d = decides(&cloud);
    assert_eq!(d.len(), 1);
    assert_eq!(d[0]["decision"], "approve");
    assert_eq!(d[0]["via"], "agent_client");
    assert_eq!(
        t.audit_lines().pop().unwrap()["confirmation"],
        "approval:agent_client"
    );

    let (t, cloud, world) = fake_cloud::server(&[], held("always", vec![], true)).await;
    let no = FakePeer::new(Elicit::Decline);
    let r = t.call(&no, SCAN, args()).await;
    assert_eq!(reason(&r), "approval_denied", "{}", r.text);
    let d = decides(&cloud);
    assert_eq!(d.len(), 1);
    assert_eq!(d[0]["decision"], "deny");
    assert!(
        world.lock().unwrap().scans.is_empty(),
        "a denied launch started"
    );

    // Dismissed: left for the approval page.
    let (t, cloud, _) = fake_cloud::server(&[], held("always", vec![], true)).await;
    let later = FakePeer::new(Elicit::Dismiss);
    let v = ok(&t.call(&later, SCAN, args()).await).clone();
    assert_eq!(v["status"], "awaiting_approval");
    assert!(decides(&cloud).is_empty());
}

#[tokio::test]
async fn a_yes_for_a_member_who_may_no_longer_launch_launches_nothing() {
    // The owner's role loses launching once the launch is held, before the person says
    // yes in the form. The platform refuses the approve, starts nothing, and leaves the
    // approval for a deny or its expiry.
    let mut w = held("always", vec![], true);
    w.demote_when_held = true;
    let (t, cloud, world) = fake_cloud::server(&[], w).await;
    assert_eq!(t.mcp.backends().cloud, Some(Listing::Launch));
    let peer = FakePeer::new(Elicit::Accept);
    let r = t.call(&peer, SCAN, args()).await;
    let v = ok(&r).clone();
    assert_eq!(peer.asked(), 1);
    let d = decides(&cloud);
    assert_eq!(d.len(), 1);
    assert_eq!(d[0]["decision"], "approve");
    // The handle as it stands and the step that failed, not a refusal that reads as if
    // nothing was asked for.
    assert_eq!(v["status"], "awaiting_approval", "{v}");
    assert!(v["scan_id"].as_str().unwrap().starts_with("ap_"), "{v}");
    assert_eq!(
        v["cloud_error"], "sending the decision failed: permission_denied",
        "{v}"
    );
    // What whoami says now decides the tools listed, and the client is told once.
    assert_eq!(
        cloud.routes().iter().filter(|r| *r == "whoami").count(),
        2,
        "{:?}",
        cloud.routes()
    );
    assert_eq!(
        peer.list_changed.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(t.mcp.backends().cloud, Some(Listing::Read));
    let w = world.lock().unwrap();
    assert!(
        w.scans.is_empty(),
        "a scan started for a member who may not launch"
    );
    assert_eq!(w.approvals.len(), 1);
    assert!(w.approvals.values().all(|a| a["status"] == "pending"));
}

#[tokio::test]
async fn the_form_is_not_offered_where_the_workspace_does_not_allow_it() {
    // A phone registered: the phone alone approves, whatever the client can show.
    let (t, cloud, _) = fake_cloud::server(&[], held("always", vec!["Pixel 8"], true)).await;
    let mut peer = FakePeer::new(Elicit::Accept);
    peer.url = Elicit::Accept;
    let v = ok(&t.call(&peer, SCAN, args()).await).clone();
    assert_eq!(v["status"], "awaiting_approval");
    assert_eq!(peer.asked(), 0);
    assert!(peer.urls.lock().unwrap().is_empty());
    assert!(decides(&cloud).is_empty());

    // No phone and the fallback off: nobody can approve it, so the platform refuses it
    // and stores nothing.
    let (t, cloud, world) = fake_cloud::server(&[], held("always", vec![], false)).await;
    let r = t.call(&peer, SCAN, args()).await;
    assert_eq!(reason(&r), "approval_required", "{}", r.text);
    assert!(r.text.contains("Register a phone"), "{}", r.text);
    assert_eq!(peer.asked(), 0);
    assert!(peer.urls.lock().unwrap().is_empty());
    assert!(decides(&cloud).is_empty());
    {
        let w = world.lock().unwrap();
        assert!(w.approvals.is_empty() && w.scans.is_empty());
    }

    // A client that can ask nothing: the page, in words.
    let (t, cloud, _) = fake_cloud::server(&[], held("always", vec![], true)).await;
    let none = FakePeer::new(Elicit::None);
    let r = t.call(&none, SCAN, args()).await;
    let v = ok(&r).clone();
    assert_eq!(v["status"], "awaiting_approval");
    assert!(r.text.contains("/m/approve/"), "{}", r.text);
    assert!(decides(&cloud).is_empty());
}

#[tokio::test]
async fn a_decision_against_the_launch_is_an_error_with_its_reason() {
    for (status, want) in [
        ("denied", "approval_denied"),
        ("expired", "approval_expired"),
    ] {
        let mut w = held("always", vec!["Pixel 8"], true);
        w.decide_on_wait = Some((1, status, "phone"));
        let (t, _, world) = fake_cloud::server(&[], w).await;
        let r = t.call(&FakePeer::new(Elicit::None), SCAN, args()).await;
        assert_eq!(reason(&r), want, "{}", r.text);
        assert!(world.lock().unwrap().scans.is_empty());
    }
    let mut w = held("always", vec!["Pixel 8"], true);
    w.decide_on_wait = Some((1, "approved", "phone"));
    w.fail_launch = Some("no_online_node");
    let (t, _, _) = fake_cloud::server(&[], w).await;
    let r = t.call(&FakePeer::new(Elicit::None), SCAN, args()).await;
    assert_eq!(reason(&r), "no_online_node", "{}", r.text);
    assert!(
        r.text.contains("\"status\":\"launch_failed\""),
        "{}",
        r.text
    );
}

#[tokio::test]
async fn a_risky_policy_still_asks_the_launch_question_first() {
    // Policy risky with a phone registered, and a launch across two nodes: the
    // once-per-process question comes first, then the approval.
    let mut w = held("risky", vec!["Pixel 8"], true);
    w.decide_on_wait = Some((1, "approved", "phone"));
    w.nodes[1]["status"] = json!("online");
    let (t, cloud, _) = fake_cloud::server(&[], w).await;
    let peer = FakePeer::new(Elicit::Accept);
    let v = ok(&t.call(&peer, SCAN, args()).await).clone();
    assert_eq!(v["approval"]["action"]["nodes"], 2, "{v}");
    assert_eq!(peer.asked(), 1);
    assert!(peer.questions.lock().unwrap()[0].contains("authorised"));
    assert_eq!(
        t.audit_lines().pop().unwrap()["confirmation"],
        "approval:phone"
    );
    assert!(cloud.routes().iter().any(|r| r == "approvals/wait"));

    // On one node a risky policy starts it at once, phone or not.
    let (t, cloud, _) = fake_cloud::server(&[], held("risky", vec!["Pixel 8"], true)).await;
    let v = ok(&t.call(&peer, SCAN, args()).await).clone();
    assert!(v["scan_id"].as_str().unwrap().starts_with("cs_"), "{v}");
    assert!(!cloud.routes().iter().any(|r| r.starts_with("approvals/")));
    // And across nodes with no phone too: nothing is held for a phone nobody has.
    let mut w = held("risky", vec![], true);
    w.nodes[1]["status"] = json!("online");
    let (t, cloud, _) = fake_cloud::server(&[], w).await;
    let v = ok(&t.call(&peer, SCAN, args()).await).clone();
    assert!(v["scan_id"].as_str().unwrap().starts_with("cs_"), "{v}");
    assert!(!cloud.routes().iter().any(|r| r.starts_with("approvals/")));
}

#[tokio::test]
async fn a_cancelled_wait_leaves_the_launch_pending() {
    let (t, _, world) = fake_cloud::server(&[], held("always", vec!["Pixel 8"], true)).await;
    let ct = tokio_util::sync::CancellationToken::new();
    let c2 = ct.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(60)).await;
        c2.cancel();
    });
    let r = t
        .call_ct(&FakePeer::new(Elicit::None), SCAN, args(), ct)
        .await;
    assert_eq!(reason(&r), "cancelled", "{}", r.text);
    assert!(r.text.contains("cancel_scan withdraws it"), "{}", r.text);
    let w = world.lock().unwrap();
    assert!(w.approvals.values().all(|a| a["status"] == "pending"));
}

#[tokio::test]
async fn the_form_shows_every_option_the_launch_carries() {
    let mut w = held("always", vec![], true);
    w.scope.push(("10.9.0.0/24".into(), true));
    let (t, _, world) = fake_cloud::server(&[], w).await;
    let yes = FakePeer::new(Elicit::Accept);
    let cases = [
        (
            "start_recon",
            json!({"domain": "example.org", "mode": "active"}),
            vec!["mode=active", "probes names under"],
        ),
        (
            "start_recon",
            json!({"domain": "example.org"}),
            vec!["mode=passive"],
        ),
        (
            "start_port_scan",
            json!({"targets": ["10.9.0.7"], "ports": "22,80,8000-8100"}),
            vec!["ports=22,80,8000-8100", "103 ports"],
        ),
        (
            "start_crawl",
            json!({"url": "https://app.example.com/", "max_depth": 2, "max_pages": 50}),
            vec!["max_depth=2", "max_pages=50"],
        ),
        (
            "start_content_discovery",
            json!({"url": "https://app.example.com/", "wordlist": "common",
                   "extensions": ["php", "bak"], "recurse": true}),
            vec!["wordlist=common", "extensions=php,bak", "recurse=true"],
        ),
        (
            "start_vuln_scan",
            json!({"urls": ["https://app.example.com/"], "severity_min": "high",
                   "tags": ["cve"]}),
            vec!["severity_min=high", "tags=cve"],
        ),
        (
            "start_authz_scan",
            json!({"url": "https://app.example.com/", "identities": ["admin", "viewer"]}),
            vec!["identities=admin,viewer"],
        ),
    ];
    for (i, (tool, args, want)) in cases.into_iter().enumerate() {
        let v = ok(&t.call(&yes, tool, args.clone()).await).clone();
        // Each ends before the next, as a key may have only five running.
        fake_cloud::end_scans(&world);
        let q = yes.questions.lock().unwrap()[i].clone();
        for w in want {
            assert!(q.contains(w), "{tool} {args}: {w} not in {q}");
        }
        assert!(!q.contains("exactly as shown"), "{q}");
        // The agent's view of the approval carries the same options.
        let opts = &v["approval"]["action"]["options"];
        assert!(opts.is_object(), "{tool}: {v}");
        if tool == "start_recon" {
            assert!(opts["mode"] == "active" || opts["mode"] == "passive", "{v}");
        }
    }
    assert_eq!(yes.asked(), 7);
}

#[tokio::test]
async fn a_launch_sent_with_nobody_asked_is_never_started_at_once() {
    // whoami said every launch waits for a person, so nobody is asked here; since then
    // the workspace went back to a policy that would start this launch at once.
    let (t, cloud, world) = fake_cloud::server(&[], held("always", vec!["Pixel 8"], true)).await;
    {
        let mut w = world.lock().unwrap();
        w.policy = "risky";
    }
    let peer = FakePeer::new(Elicit::Accept);
    let v = ok(&t.call(&peer, SCAN, args()).await).clone();
    assert_eq!(v["status"], "awaiting_approval", "{v}");
    assert!(v["scan_id"].as_str().unwrap().starts_with("ap_"), "{v}");
    assert_eq!(peer.asked(), 0);
    assert!(
        world.lock().unwrap().scans.is_empty(),
        "a launch started with nobody asked"
    );
    let starts: Vec<Value> = cloud
        .requests()
        .into_iter()
        .filter(|r| r.route == "scans/start")
        .map(|r| r.body)
        .collect();
    assert_eq!(starts.len(), 1);
    assert_eq!(starts[0]["hold_for_approval"], true);

    // Where the question is asked, nothing is held on its account.
    let (t, cloud, _) = fake_cloud::server(&[], World::new("launch")).await;
    let v = ok(&t.call(&peer, SCAN, args()).await).clone();
    assert!(v["scan_id"].as_str().unwrap().starts_with("cs_"), "{v}");
    assert_eq!(peer.asked(), 1);
    let sent = cloud
        .requests()
        .into_iter()
        .find(|r| r.route == "scans/start")
        .unwrap();
    assert!(
        sent.body.get("hold_for_approval").is_none(),
        "{}",
        sent.body
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_launch_open_when_the_server_stops_keeps_its_cloud_fields() {
    let mut w = held("always", vec!["Pixel 8"], true);
    w.wait_delay = std::time::Duration::from_millis(800);
    let (t, cloud, _) = fake_cloud::server(&[], w).await;
    let t = std::sync::Arc::new(t);
    let t2 = std::sync::Arc::clone(&t);
    let call =
        tokio::spawn(async move { t2.call(&FakePeer::new(Elicit::None), SCAN, args()).await });
    eventually("the wait for a decision", 5, || {
        cloud.routes().iter().any(|r| r == "approvals/wait")
    })
    .await;
    t.mcp.shutdown().await;

    let calls = |t: &TestMcp| -> Vec<Value> {
        t.audit_lines()
            .into_iter()
            .filter(|l| l["event"] == "call")
            .collect()
    };
    let lines = calls(&t);
    assert_eq!(lines.len(), 1, "{lines:#?}");
    let l = &lines[0];
    assert_eq!(l["decision"], "interrupted", "{l}");
    assert_eq!(l["backend"], "cloud", "{l}");
    assert_eq!(l["key_prefix"], "cfm_01234567", "{l}");
    assert_eq!(l["workspace_id"], fake_cloud::WORKSPACE, "{l}");
    assert!(l["approval_id"].as_str().unwrap().starts_with("ap_"), "{l}");
    assert_eq!(l["scan_id"], l["approval_id"]);
    // scans/start was answered, so the platform's record of it can be matched.
    assert!(
        l["cloud_call_id"].as_str().unwrap().starts_with("call-"),
        "{l}"
    );
    assert!(!t.audit_text().contains(&fake_cloud::KEY[4..]));

    // The call ends later and writes no second line.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), call).await;
    assert_eq!(calls(&t).len(), 1, "{:#?}", calls(&t));
}

#[tokio::test]
async fn the_same_launch_is_one_approval_and_a_denial_stands() {
    // Waiting on the phone: asked for again, it is the same approval, not a second one.
    let (t, _, world) = fake_cloud::server(&[], held("always", vec!["Pixel 8"], true)).await;
    let peer = FakePeer::new(Elicit::None);
    let first = ok(&t.call(&peer, SCAN, args()).await).clone();
    let again = ok(&t.call(&peer, SCAN, args()).await).clone();
    assert_eq!(first["scan_id"], again["scan_id"]);
    assert_eq!(world.lock().unwrap().approvals.len(), 1);

    // Denied in the client's form, then asked for again: the platform answers with the
    // denial, and nobody is asked a second time.
    let (t, cloud, world) = fake_cloud::server(&[], held("always", vec![], true)).await;
    let no = FakePeer::new(Elicit::Decline);
    let r = t.call(&no, SCAN, args()).await;
    assert_eq!(reason(&r), "approval_denied", "{}", r.text);
    let r = t.call(&no, SCAN, args()).await;
    assert_eq!(reason(&r), "approval_denied", "{}", r.text);
    assert!(r.text.contains("did not ask again"), "{}", r.text);
    assert!(r.text.contains("\"denied_before\":true"), "{}", r.text);
    assert_eq!(no.asked(), 1, "the person was asked again");
    assert_eq!(decides(&cloud).len(), 1);
    let w = world.lock().unwrap();
    assert_eq!(w.approvals.len(), 1);
    assert!(w.scans.is_empty());
}

#[tokio::test]
async fn too_many_launches_waiting_is_a_limit_on_launches() {
    let (t, cloud, _) = fake_cloud::server(&[], held("always", vec!["Pixel 8"], true)).await;
    let peer = FakePeer::new(Elicit::None);
    for path in ["a", "b", "c"] {
        let urls = json!({"urls": [format!("https://app.example.com/{path}")]});
        let v = ok(&t.call(&peer, SCAN, urls).await).clone();
        assert_eq!(v["status"], "awaiting_approval");
    }
    let r = t
        .call(&peer, SCAN, json!({"urls": ["https://app.example.com/d"]}))
        .await;
    assert_eq!(reason(&r), "rate_limited", "{}", r.text);
    let said = r.text.lines().next().unwrap();
    assert!(said.contains("launches"), "{said}");
    assert!(r.text.contains("\"retry_after_seconds\":60"), "{}", r.text);
    assert!(
        r.text
            .contains("Too many launches are waiting for approval"),
        "{}",
        r.text
    );
    // Each waiting launch is a row of list_scans, with the handle that follows it.
    let v = ok(&t
        .call(&peer, "list_scans", json!({"backend": "cloud"}))
        .await)
    .clone();
    let rows = v["scans"].as_array().unwrap();
    assert_eq!(rows.len(), 3, "{v}");
    assert!(
        rows.iter().all(|s| s["status"] == "awaiting_approval"
            && s["scan_id"].as_str().unwrap().starts_with("ap_"))
    );
    assert_eq!(
        cloud
            .routes()
            .iter()
            .filter(|r| *r == "scans/start")
            .count(),
        4
    );
}

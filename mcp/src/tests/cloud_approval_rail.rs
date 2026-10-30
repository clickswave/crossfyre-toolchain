//! A launch the workspace holds for a person: the call waits on the owner's phone when
//! there is one, asks in the agent's client only when there is none and the workspace
//! allows it, and otherwise hands back where the launch can be decided.

use super::fake_cloud::{self, World};
use super::support::*;
use serde_json::{Value, json};

fn held(policy: &'static str, phones: Vec<&'static str>, fallback: bool) -> World {
    let mut w = World::new("launch");
    w.approval_required = true;
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
    assert!(q.contains("2 node(s) of Acme staging"), "{q}");
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

    // No phone and the fallback off.
    let (t, cloud, _) = fake_cloud::server(&[], held("always", vec![], false)).await;
    let v = ok(&t.call(&peer, SCAN, args()).await).clone();
    assert_eq!(v["status"], "awaiting_approval");
    assert_eq!(peer.asked(), 0);
    assert!(decides(&cloud).is_empty());

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
    // Approval needed, policy risky: the once-per-process question comes first, then
    // the approval.
    let mut w = held("risky", vec!["Pixel 8"], true);
    w.decide_on_wait = Some((1, "approved", "phone"));
    let (t, _, _) = fake_cloud::server(&[], w).await;
    let peer = FakePeer::new(Elicit::Accept);
    ok(&t.call(&peer, SCAN, args()).await);
    assert_eq!(peer.asked(), 1);
    assert!(peer.questions.lock().unwrap()[0].contains("authorised"));
    assert_eq!(
        t.audit_lines().pop().unwrap()["confirmation"],
        "approval:phone"
    );
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

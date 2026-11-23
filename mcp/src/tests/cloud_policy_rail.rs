//! The machine's privacy policy, as the Cloud backend applies it before any call.

use super::fake_cloud::{self, World};
use super::support::*;
use serde_json::json;

fn policy(t: &TestMcp, state: &str) {
    std::fs::write(t.dir.path().join("policy.toml"), state).unwrap();
}

const PRIVATE: &str = "account = \"private\"\n";
const OFFLINE: &str = "[offline]\nreason = \"chosen\"\nsince = \"2026-11-22T05:30:07Z\"\n";

/// Under private, a call that would carry a target is refused here and sends nothing; a
/// read still goes. The policy is read on every call, so a change holds from the next.
#[tokio::test]
async fn private_sends_no_target_to_the_cloud_and_reads_still_go() {
    let (t, cloud, world) = fake_cloud::server(&[], World::new("launch")).await;
    let peer = FakePeer::new(Elicit::None);
    policy(&t, PRIVATE);
    let before = cloud.requests().len();
    let r = t
        .call(
            &peer,
            "start_crawl",
            json!({"url": "https://app.example.com/"}),
        )
        .await;
    assert_eq!(reason(&r), "policy_private", "{}", r.text);
    assert!(
        r.text.contains("policy: private (the account's)."),
        "{}",
        r.text
    );
    assert!(
        r.text.contains("Nothing was sent to the Cloud."),
        "{}",
        r.text
    );
    // A tool that answers from here as well as the Cloud answers from here, and says
    // why the Cloud's half is missing.
    let v = ok(&t
        .call(
            &peer,
            "check_scope",
            json!({"targets": ["app.example.com"]}),
        )
        .await)
    .clone();
    let why = v["cloud_error"].as_str().unwrap_or_default();
    assert!(why.starts_with("policy: private (the account's)."), "{v}");
    assert_eq!(
        cloud.requests().len(),
        before,
        "a refused call reached the Cloud"
    );
    assert!(world.lock().unwrap().started.is_empty());
    let r = t.call(&peer, "list_scans", json!({})).await;
    ok(&r);
    assert_eq!(cloud.requests().len(), before + 1);

    policy(&t, "");
    let r = t
        .call(
            &peer,
            "start_crawl",
            json!({"url": "https://app.example.com/"}),
        )
        .await;
    ok(&r);
    assert_eq!(world.lock().unwrap().started.len(), 1);
}

/// Offline, every Cloud tool answers here and nothing is asked of the Cloud, reads
/// included.
#[tokio::test]
async fn offline_asks_the_cloud_nothing() {
    let (t, cloud, _) = fake_cloud::server(&[], World::new("launch")).await;
    let peer = FakePeer::new(Elicit::None);
    policy(&t, OFFLINE);
    let before = cloud.requests().len();
    let r = t
        .call(
            &peer,
            "start_crawl",
            json!({"url": "https://app.example.com/"}),
        )
        .await;
    assert_eq!(reason(&r), "policy_offline", "{}", r.text);
    assert!(
        r.text.contains("policy: offline (you chose it)."),
        "{}",
        r.text
    );
    let v = ok(&t.call(&peer, "list_scans", json!({})).await).clone();
    let why = v["cloud_error"].as_str().unwrap_or_default();
    assert!(why.starts_with("policy: offline (you chose it)."), "{v}");
    assert_eq!(
        cloud.requests().len(),
        before,
        "an offline machine asked the Cloud"
    );
}

/// Started on an offline machine, the backend asks nothing, not even who the key is,
/// and lists the tools the last login cached, so the agent learns why from them.
#[tokio::test]
async fn an_offline_start_asks_nothing_and_lists_what_was_cached() {
    let cloud = fake_cloud::FakeCloud::start(fake_cloud::account("launch")).await;
    let mut t = scope(&[], "").build();
    policy(&t, OFFLINE);
    fake_cloud::connect(&mut t, &cloud.url(), Some("launch")).await;
    assert!(cloud.requests().is_empty(), "{:?}", cloud.requests());
    assert_eq!(t.mcp.backends().cloud, Some(crate::cloud::Listing::Launch));
}

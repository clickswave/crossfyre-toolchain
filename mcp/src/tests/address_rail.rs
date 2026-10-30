//! A name in scope still does not reach a private address unless the file says so.
//!
//! The scope file lists destinations; the address check decides which addresses of a
//! listed name may be dialled. A public-looking name that resolves to loopback, or to
//! a cloud metadata service, is how a scan gets turned around on the machine running
//! it.

use super::support::*;
use crate::guard::{AddrRefusal, parse_target, resolve_checked};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_name_resolving_to_loopback_is_refused_without_allow_private() {
    let target = listener(Reply::ok("x")).await;
    let names = FakeResolver::default().with("internal.test", &["127.0.0.1"]);
    let t = scope(&["internal.test".into()], "").resolver(names).build();
    let r = t
        .call(
            &FakePeer::new(Elicit::None),
            "send_http_request",
            json!({"method": "GET", "url": format!("http://internal.test:{}/", target.port)}),
        )
        .await;
    assert_eq!(
        target.conns(),
        0,
        "a name resolving to loopback was dialled"
    );
    assert_eq!(reason(&r), "private_address");
    assert!(
        !r.text.contains("127.0.0.1"),
        "the address is not named: {}",
        r.text
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn allow_private_lets_it_through() {
    let target = listener(Reply::ok("x")).await;
    let names = FakeResolver::default().with("internal.test", &["127.0.0.1"]);
    let t = scope(&["internal.test".into()], "allow_private = true")
        .resolver(names)
        .build();
    let r = t
        .call(
            &FakePeer::new(Elicit::None),
            "send_http_request",
            json!({"method": "GET", "url": format!("http://internal.test:{}/", target.port)}),
        )
        .await;
    ok(&r);
    assert_eq!(target.conns(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_address_listed_by_itself_is_its_own_permission() {
    let target = listener(Reply::ok("x")).await;
    let t = scope(&[format!("127.0.0.1:{}", target.port)], "").build();
    let r = t
        .call(
            &FakePeer::new(Elicit::None),
            "send_http_request",
            json!({"method": "GET", "url": format!("http://127.0.0.1:{}/", target.port)}),
        )
        .await;
    ok(&r);
    assert_eq!(target.conns(), 1);
}

#[tokio::test]
async fn metadata_is_refused_even_with_allow_private_unless_listed() {
    let names = FakeResolver::default().with("meta.test", &["169.254.169.254"]);
    let d = parse_target("http://meta.test/latest/").unwrap();
    let (s, _) = cfx_scope::parse(&["meta.test".to_string()]);
    assert_eq!(
        resolve_checked(&names, &d, &s, true).await,
        Err(AddrRefusal::Metadata)
    );
    let (s, _) = cfx_scope::parse(&["meta.test".to_string(), "169.254.169.254".to_string()]);
    assert_eq!(
        resolve_checked(&names, &d, &s, true).await.unwrap(),
        vec![sock("169.254.169.254", 80)]
    );
}

#[tokio::test]
async fn a_name_with_public_and_private_addresses_is_pinned_to_the_public_one() {
    let names = FakeResolver::default().with("split.test", &["10.0.0.5", "93.184.216.34"]);
    let d = parse_target("https://split.test/").unwrap();
    let (s, _) = cfx_scope::parse(&["split.test".to_string()]);
    assert_eq!(
        resolve_checked(&names, &d, &s, false).await.unwrap(),
        vec![sock("93.184.216.34", 443)]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plessor_is_asked_to_filter_internal_addresses_for_names() {
    // No simulated traffic here: the name resolves to a public address, and nothing
    // in a test goes to the internet. Only the request to the engine is inspected.
    let plessor = stub_engine(StubOpts::default()).await;
    let names = FakeResolver::default().with("app.test", &["93.184.216.34"]);
    let target = listener(Reply::ok("x")).await;
    let t = scope(
        &["app.test".into(), format!("127.0.0.1:{}", target.port)],
        "",
    )
    .resolver(names)
    .plessor(plessor.port)
    .build();
    let peer = FakePeer::new(Elicit::None);
    ok(&t
        .call(
            &peer,
            "test_injection",
            json!({"url": "http://app.test/?q=1"}),
        )
        .await);
    ok(&t
        .call(
            &peer,
            "test_injection",
            json!({"url": format!("http://127.0.0.1:{}/?q=1", target.port)}),
        )
        .await);
    let ops = plessor.ops();
    assert_eq!(ops[0]["block_internal"], true, "{}", ops[0]);
    assert_eq!(ops[1]["block_internal"], false, "{}", ops[1]);
}

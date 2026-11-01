//! A person is asked before traffic, once; and every time before a write.

use super::support::*;
use serde_json::json;

async fn get(t: &TestMcp, peer: &FakePeer, port: u16) -> crate::core::ToolResult {
    t.call(
        peer,
        "send_http_request",
        json!({"method": "GET", "url": format!("http://127.0.0.1:{port}/")}),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_yes_is_asked_for_once_per_process() {
    let target = listener(Reply::ok("x")).await;
    let t = scope(&[format!("127.0.0.1:{}", target.port)], "").build();
    let peer = FakePeer::new(Elicit::Accept);
    ok(&get(&t, &peer, target.port).await);
    ok(&get(&t, &peer, target.port).await);
    assert_eq!(peer.asked(), 1);
    let q = peer.questions.lock().unwrap()[0].clone();
    assert!(q.contains(&format!("127.0.0.1:{}", target.port)), "{q}");
    assert!(q.contains("authorised"), "{q}");
    let lines = t.audit_lines();
    assert!(lines.iter().all(|l| l["confirmation"] == "elicited"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_no_is_remembered_and_nothing_is_sent() {
    let target = listener(Reply::ok("x")).await;
    let t = scope(&[format!("127.0.0.1:{}", target.port)], "").build();
    let peer = FakePeer::new(Elicit::Decline);
    assert_eq!(reason(&get(&t, &peer, target.port).await), "declined");
    let again = get(&t, &peer, target.port).await;
    assert_eq!(reason(&again), "declined");
    assert!(
        again.text.to_lowercase().contains("restart"),
        "{}",
        again.text
    );
    assert_eq!(
        peer.asked(),
        1,
        "a model retrying must not become a stream of questions"
    );
    assert_eq!(target.conns(), 0);
    assert!(
        t.audit_lines()
            .iter()
            .all(|l| l["confirmation"] == "declined")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_that_cannot_ask_relies_on_the_file() {
    let target = listener(Reply::ok("x")).await;
    let t = scope(&[format!("127.0.0.1:{}", target.port)], "").build();
    ok(&get(&t, &FakePeer::new(Elicit::None), target.port).await);
    assert_eq!(t.audit_lines()[0]["confirmation"], "file");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_writes_needs_the_file_and_a_yes_each_time() {
    let target = listener(Reply::ok("x")).await;
    let plessor = stub_engine(StubOpts::default()).await;
    let args =
        json!({"url": format!("http://127.0.0.1:{}/?q=1", target.port), "test_writes": true});

    // Not allowed by the file: refused before anybody is asked.
    let t = scope(&[format!("127.0.0.1:{}", target.port)], "")
        .plessor(plessor.port)
        .build();
    let peer = FakePeer::new(Elicit::Accept);
    assert_eq!(
        reason(&t.call(&peer, "test_injection", args.clone()).await),
        "writes_not_allowed"
    );
    assert_eq!(peer.asked(), 0);
    assert_eq!(plessor.ops().len(), 0);

    // Allowed, and the person says yes: asked for the scope and for the write.
    let t = scope(
        &[format!("127.0.0.1:{}", target.port)],
        "allow_writes = true",
    )
    .plessor(plessor.port)
    .build();
    let peer = FakePeer::new(Elicit::Accept);
    ok(&t.call(&peer, "test_injection", args.clone()).await);
    assert_eq!(peer.asked(), 2);
    assert!(peer.questions.lock().unwrap()[1].contains("DELETE, PUT and PATCH"));
    assert_eq!(plessor.ops()[0]["test_writes"], true);
    ok(&t.call(&peer, "test_injection", args.clone()).await);
    assert_eq!(peer.asked(), 3, "a write is confirmed every time");

    // Allowed, but this client cannot ask: refused.
    let t = scope(
        &[format!("127.0.0.1:{}", target.port)],
        "allow_writes = true",
    )
    .plessor(plessor.port)
    .build();
    let before = plessor.ops().len();
    assert_eq!(
        reason(
            &t.call(&FakePeer::new(Elicit::None), "test_injection", args)
                .await
        ),
        "not_confirmed"
    );
    assert_eq!(plessor.ops().len(), before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_write_method_is_confirmed_once_per_host_and_port() {
    let a = listener(Reply::ok("a")).await;
    let b = listener(Reply::ok("b")).await;
    let t = scope(
        &[
            format!("127.0.0.1:{}", a.port),
            format!("127.0.0.1:{}", b.port),
        ],
        "allow_writes = true",
    )
    .build();
    let peer = FakePeer::new(Elicit::Accept);
    let post = |port: u16| json!({"method": "POST", "url": format!("http://127.0.0.1:{port}/x"), "body": "a=1"});
    ok(&t.call(&peer, "send_http_request", post(a.port)).await);
    ok(&t.call(&peer, "send_http_request", post(a.port)).await);
    assert_eq!(peer.asked(), 2, "the scope once, then this host once");
    ok(&t.call(&peer, "send_http_request", post(b.port)).await);
    assert_eq!(peer.asked(), 3, "another host is asked about separately");
    assert_eq!((a.conns(), b.conns()), (2, 1));

    let denied = FakePeer::new(Elicit::None);
    let t = scope(&[format!("127.0.0.1:{}", a.port)], "allow_writes = true").build();
    assert_eq!(
        reason(&t.call(&denied, "send_http_request", post(a.port)).await),
        "not_confirmed"
    );
    let t = scope(&[format!("127.0.0.1:{}", a.port)], "").build();
    assert_eq!(
        reason(&t.call(&peer, "send_http_request", post(a.port)).await),
        "writes_not_allowed"
    );
    assert_eq!(a.conns(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_call_cancelled_while_asking_ends_at_once_and_is_not_a_no() {
    let target = listener(Reply::ok("x")).await;
    let t = scope(&[format!("127.0.0.1:{}", target.port)], "").build();
    let ct = tokio_util::sync::CancellationToken::new();
    let stop = ct.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        stop.cancel();
    });
    let r = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        t.call_ct(
            &FakePeer::new(Elicit::Hang),
            "send_http_request",
            json!({"method": "GET", "url": format!("http://127.0.0.1:{}/", target.port)}),
            ct,
        ),
    )
    .await
    .expect("the call waited out the confirmation after it was cancelled");
    assert_eq!(reason(&r), "cancelled");
    assert_eq!(target.conns(), 0);

    // Nobody said no, so the next call asks again.
    let peer = FakePeer::new(Elicit::Accept);
    ok(&get(&t, &peer, target.port).await);
    assert_eq!(peer.asked(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dismissed_question_refuses_that_call_and_is_asked_again() {
    let target = listener(Reply::ok("x")).await;
    let t = scope(&[format!("127.0.0.1:{}", target.port)], "").build();
    let r = get(&t, &FakePeer::new(Elicit::Dismiss), target.port).await;
    assert_eq!(reason(&r), "not_confirmed");
    assert_eq!(target.conns(), 0);
    assert_eq!(t.audit_lines()[0]["confirmation"], "not_answered");

    let peer = FakePeer::new(Elicit::Accept);
    ok(&get(&t, &peer, target.port).await);
    assert_eq!(peer.asked(), 1, "a dismissal is not a no");
}

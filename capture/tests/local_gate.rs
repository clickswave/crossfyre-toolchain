//! The in-process intercept gate, on its own.
//!
//! Driving it through the proxy is in `proxy_conformance.rs`, because that is where the
//! harness lives and where "the origin never saw it" can be asserted. What is here is the
//! queue's own behaviour: ordering, the arrival signal a UI waits on, and what happens to
//! a request nobody answers, which is the half that decides whether interception is a
//! promise or a suggestion.

use std::sync::Arc;
use std::time::Duration;

use cfx_capture::{EditedRequest, InterceptDecision, InterceptGate, LocalGate};

/// Park a request on `gate` and hand back the task awaiting the verdict.
fn hold(
    gate: Arc<LocalGate>,
    method: &str,
    url: &str,
) -> tokio::task::JoinHandle<InterceptDecision> {
    let method = method.to_string();
    let url = url.to_string();
    tokio::spawn(async move {
        gate.decide(&method, &url, &[("host".into(), "x.test".into())], b"body")
            .await
    })
}

/// Wait until `n` requests are queued, so a test never races the task that parks them.
async fn until_pending(gate: &LocalGate, n: usize) {
    for _ in 0..500 {
        if gate.pending_count() >= n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    panic!(
        "only {} of {n} requests were ever queued",
        gate.pending_count()
    );
}

#[tokio::test]
async fn a_held_request_is_visible_and_resolving_it_releases_the_caller() {
    let gate = Arc::new(LocalGate::new());
    let task = hold(gate.clone(), "POST", "https://x.test/login?next=2");
    until_pending(&gate, 1).await;

    let waiting = gate.pending();
    assert_eq!(waiting.len(), 1);
    let h = &waiting[0];
    assert_eq!(h.method, "POST");
    assert_eq!(
        h.url, "https://x.test/login?next=2",
        "the operator is shown the real URL, values included, because that is what they \
         are being asked to approve"
    );
    assert_eq!(h.body, b"body");
    assert!(h.headers.iter().any(|(k, _)| k == "host"));

    assert!(gate.resolve(h.id, InterceptDecision::Forward));
    assert_eq!(
        task.await.expect("no panic"),
        InterceptDecision::Forward,
        "the parked request got the decision"
    );
    assert_eq!(gate.pending_count(), 0, "and left the queue");
}

#[tokio::test]
async fn an_edited_request_comes_back_through_the_gate_intact() {
    let gate = Arc::new(LocalGate::new());
    let task = hold(gate.clone(), "GET", "https://x.test/original");
    until_pending(&gate, 1).await;
    let id = gate.pending()[0].id;

    let edited = EditedRequest {
        method: "PUT".into(),
        path: "/edited".into(),
        headers: vec![("host".into(), "x.test".into())],
        body: b"operator typed this".to_vec(),
    };
    assert!(gate.resolve(id, InterceptDecision::ForwardModified(edited.clone())));
    assert_eq!(
        task.await.expect("no panic"),
        InterceptDecision::ForwardModified(edited)
    );
}

#[tokio::test]
async fn the_queue_is_oldest_first_and_resolving_out_of_order_works() {
    let gate = Arc::new(LocalGate::new());
    let a = hold(gate.clone(), "GET", "https://x.test/first");
    until_pending(&gate, 1).await;
    let b = hold(gate.clone(), "GET", "https://x.test/second");
    until_pending(&gate, 2).await;
    let c = hold(gate.clone(), "GET", "https://x.test/third");
    until_pending(&gate, 3).await;

    let urls: Vec<String> = gate.pending().into_iter().map(|h| h.url).collect();
    assert_eq!(
        urls,
        [
            "https://x.test/first",
            "https://x.test/second",
            "https://x.test/third"
        ],
        "a queue a human works through has to be in the order things arrived"
    );

    // The middle one first, which is what clicking a row in the middle does.
    let ids: Vec<u64> = gate.pending().into_iter().map(|h| h.id).collect();
    assert!(gate.resolve(ids[1], InterceptDecision::Drop));
    assert_eq!(b.await.expect("no panic"), InterceptDecision::Drop);
    assert_eq!(
        gate.pending()
            .into_iter()
            .map(|h| h.url)
            .collect::<Vec<_>>(),
        ["https://x.test/first", "https://x.test/third"],
        "and the rest keep their order"
    );

    gate.resolve(ids[0], InterceptDecision::Forward);
    gate.resolve(ids[2], InterceptDecision::Forward);
    assert_eq!(a.await.unwrap(), InterceptDecision::Forward);
    assert_eq!(c.await.unwrap(), InterceptDecision::Forward);
}

#[tokio::test]
async fn resolving_something_that_is_not_waiting_says_so() {
    let gate = Arc::new(LocalGate::new());
    // A UI acting on a stale list, or a second click on the same row.
    assert!(!gate.resolve(999, InterceptDecision::Forward));

    let task = hold(gate.clone(), "GET", "https://x.test/a");
    until_pending(&gate, 1).await;
    let id = gate.pending()[0].id;
    assert!(gate.resolve(id, InterceptDecision::Forward));
    assert!(
        !gate.resolve(id, InterceptDecision::Drop),
        "the same id does not resolve twice, so a double click cannot turn a forwarded \
         request into a dropped one"
    );
    assert_eq!(task.await.unwrap(), InterceptDecision::Forward);
}

#[tokio::test]
async fn resolve_all_answers_everything_waiting() {
    let gate = Arc::new(LocalGate::new());
    let tasks: Vec<_> = (0..5)
        .map(|i| hold(gate.clone(), "GET", &format!("https://x.test/{i}")))
        .collect();
    until_pending(&gate, 5).await;

    assert_eq!(gate.resolve_all(InterceptDecision::Forward), 5);
    assert_eq!(gate.pending_count(), 0);
    for t in tasks {
        assert_eq!(t.await.unwrap(), InterceptDecision::Forward);
    }
}

#[tokio::test]
async fn the_arrival_signal_does_not_miss_a_request_that_already_landed() {
    let gate = Arc::new(LocalGate::new());

    // Nothing waiting: the signal blocks until something does.
    let g = gate.clone();
    let waiter = tokio::spawn(async move { g.arrival().await });
    let task = hold(gate.clone(), "GET", "https://x.test/a");
    tokio::time::timeout(Duration::from_secs(5), waiter)
        .await
        .expect("the arrival signal fired")
        .expect("no panic");

    // Already waiting: it returns at once rather than blocking for the NEXT one. Without
    // this a UI that checked the queue, found it empty, and then awaited would sit there
    // while a request it had already been sent went unanswered.
    until_pending(&gate, 1).await;
    tokio::time::timeout(Duration::from_millis(200), gate.arrival())
        .await
        .expect("an already-queued request satisfies the signal immediately");

    gate.resolve_all(InterceptDecision::Forward);
    task.await.unwrap();
}

#[tokio::test]
async fn shutdown_drops_what_is_held_and_what_arrives_after() {
    let gate = Arc::new(LocalGate::new());
    let held = hold(gate.clone(), "POST", "https://x.test/in-flight");
    until_pending(&gate, 1).await;

    assert_eq!(
        gate.shutdown(),
        1,
        "the in-flight request was accounted for"
    );
    assert_eq!(
        held.await.unwrap(),
        InterceptDecision::Drop,
        "a request released because the UI went away is one nobody looked at, so it does \
         not go to the target"
    );
    assert!(gate.is_shut_down());

    // And a flow that arrives a moment later is not parked for a window that has gone.
    let late = hold(gate.clone(), "GET", "https://x.test/late");
    assert_eq!(late.await.unwrap(), InterceptDecision::Drop);
    assert_eq!(gate.pending_count(), 0, "nothing queues after shutdown");
}

#[tokio::test]
async fn with_no_timeout_a_request_waits_rather_than_being_forwarded() {
    // The promise interception makes. A gate that let this through after a while would
    // put a request the operator never saw into their own evidence.
    let gate = Arc::new(LocalGate::new());
    let task = hold(gate.clone(), "GET", "https://x.test/unanswered");
    until_pending(&gate, 1).await;

    assert!(
        tokio::time::timeout(Duration::from_millis(400), task)
            .await
            .is_err(),
        "it is still waiting, not forwarded"
    );
    assert_eq!(gate.pending_count(), 1);
}

#[tokio::test]
async fn a_timeout_applies_the_action_the_host_chose() {
    let gate = Arc::new(LocalGate::with_timeout(
        Duration::from_millis(150),
        InterceptDecision::Drop,
    ));
    let task = hold(gate.clone(), "GET", "https://x.test/slow");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the timeout fired")
            .unwrap(),
        InterceptDecision::Drop
    );
    assert_eq!(
        gate.pending_count(),
        0,
        "an expired hold leaves the queue, or a UI shows a row nobody is waiting on"
    );

    // And a host that wants the other trade gets it.
    let open = Arc::new(LocalGate::with_timeout(
        Duration::from_millis(150),
        InterceptDecision::Forward,
    ));
    let task = hold(open.clone(), "GET", "https://x.test/slow");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the timeout fired")
            .unwrap(),
        InterceptDecision::Forward
    );
}

#[tokio::test]
async fn a_decision_beats_a_timeout_that_has_not_expired() {
    let gate = Arc::new(LocalGate::with_timeout(
        Duration::from_secs(30),
        InterceptDecision::Drop,
    ));
    let task = hold(gate.clone(), "GET", "https://x.test/quick");
    until_pending(&gate, 1).await;
    let id = gate.pending()[0].id;
    assert!(gate.resolve(id, InterceptDecision::Forward));
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("resolved well inside the deadline")
            .unwrap(),
        InterceptDecision::Forward
    );
}

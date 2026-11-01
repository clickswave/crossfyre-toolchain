//! A redirect is a new destination, and is checked as one.
//!
//! A target in scope can answer `302 Location: <anywhere>`. A client that follows it
//! on its own has let the target choose where the next request goes, so the server
//! follows redirects itself, only when asked, and puts every hop through the guard
//! before anything is sent to it.

use super::support::*;
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_redirect_out_of_scope_is_not_followed() {
    let outside = listener(Reply::ok("out")).await;
    let inside = listener(Reply::Redirect(format!(
        "http://127.0.0.1:{}/",
        outside.port
    )))
    .await;
    let t = scope(
        &[format!("127.0.0.1:{}", inside.port)],
        "allow_private = true",
    )
    .build();
    let peer = FakePeer::new(Elicit::None);
    let url = format!("http://127.0.0.1:{}/start", inside.port);

    let r = t
        .call(
            &peer,
            "send_http_request",
            json!({"method": "GET", "url": url}),
        )
        .await;
    assert_eq!(
        outside.conns(),
        0,
        "a redirect was followed without being asked"
    );
    let v = ok(&r);
    assert_eq!(v["status"], 302);
    assert!(v.get("redirect_refused").is_none());

    let r = t
        .call(
            &peer,
            "send_http_request",
            json!({"method": "GET", "url": url, "follow_redirects": true}),
        )
        .await;
    assert_eq!(outside.conns(), 0, "the hop out of scope was sent");
    let v = ok(&r);
    assert_eq!(v["status"], 302);
    assert_eq!(v["redirect_refused"]["reason"], "redirect_out_of_scope");
    assert_eq!(
        v["target_data"]["refused_location"],
        format!("http://127.0.0.1:{}/", outside.port)
    );

    let line = t.audit_lines().into_iter().last().unwrap();
    assert_eq!(line["decision"], "ok");
    assert_eq!(line["refused"][0]["at"], "redirect_hop");
    assert_eq!(line["refused"][0]["port"], outside.port);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_redirect_within_scope_is_followed_without_the_credentials() {
    let second = listener(Reply::ok("second")).await;
    let first = listener(Reply::Redirect(format!(
        "http://127.0.0.1:{}/next",
        second.port
    )))
    .await;
    let t = scope(
        &[
            format!("127.0.0.1:{}", first.port),
            format!("127.0.0.1:{}", second.port),
        ],
        "allow_private = true",
    )
    .build();
    let r = t
        .call(
            &FakePeer::new(Elicit::None),
            "send_http_request",
            json!({
                "method": "GET",
                "url": format!("http://127.0.0.1:{}/", first.port),
                "follow_redirects": true,
                "headers": {"Authorization": "Bearer abc.def", "X-Trace": "1"},
            }),
        )
        .await;
    let v = ok(&r);
    assert_eq!(v["status"], 200);
    assert_eq!(v["redirect_count"], 1);
    assert_eq!(second.conns(), 1);
    let sent = second.last_request().to_ascii_lowercase();
    assert!(sent.starts_with("get /next "), "{sent}");
    assert!(
        !sent.contains("authorization"),
        "credentials crossed origins: {sent}"
    );
    assert!(sent.contains("x-trace: 1"));
}

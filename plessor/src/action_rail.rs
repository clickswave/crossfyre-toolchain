//! The two request guards in the injection pass have to run before anything is sent.
//!
//! `names_an_action` skips a link whose query names an action, and
//! `changes_a_credential` strips the fields that would set a password. Both sat
//! after the inventory, rate-limit, CORS, XXE and exposure probes, and those
//! probes send the endpoint's URL as recorded, query string included. So a
//! `?action=delete` link was requested by the CORS probe before the guard that
//! says it must never be requested, and DVWA's password-change link went out with
//! its password fields still on it.
//!
//! As in writes_rail, this counts what arrives at a socket rather than testing
//! any probe's reasoning, and it asserts both directions: nothing guarded
//! arrives, and an ordinary endpoint beside it is still probed, so the test
//! cannot pass on a pass that has stopped sending anything.

use serde_json::json;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

/// A listener that answers everything and keeps every request line it saw.
async fn recording_target() -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let lines = Arc::new(Mutex::new(Vec::new()));
    let kept = Arc::clone(&lines);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let kept = Arc::clone(&kept);
            tokio::spawn(async move {
                let mut buf = [0u8; 16384];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            let head = String::from_utf8_lossy(&buf[..n]);
                            let first = head.lines().next().unwrap_or("").to_string();
                            kept.lock().expect("lock").push(first);
                            let body = br#"{"ok":true,"id":1}"#;
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                                 Access-Control-Allow-Origin: *\r\n\
                                 Content-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                                body.len()
                            );
                            if sock.write_all(resp.as_bytes()).await.is_err()
                                || sock.write_all(body).await.is_err()
                            {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    (format!("http://{addr}"), lines)
}

async fn run_pass(endpoints: serde_json::Value) -> Vec<String> {
    let (base, lines) = recording_target().await;
    let endpoints: Vec<serde_json::Value> = endpoints
        .as_array()
        .expect("array")
        .iter()
        .map(|e| {
            let mut e = e.clone();
            let url = e["url"].as_str().expect("url").replace("BASE", &base);
            e["url"] = json!(url);
            e
        })
        .collect();
    // No classes named, so every default probe runs, which is the case that
    // matters: inventory, rate limit, CORS, XXE and exposure all run by default.
    let params = serde_json::from_value(json!({
        "target": base, "evasive": false, "timeout_ms": 2000, "tasks": 1,
        "endpoints": endpoints,
    }))
    .expect("inject params");
    let (tx, mut rx) = mpsc::unbounded_channel();
    crate::inject::run(params, tx).await;
    while rx.try_recv().is_ok() {}
    lines.lock().expect("lock").clone()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_link_that_names_an_action_is_never_requested() {
    let seen = run_pass(json!([
        {"method": "GET", "url": "BASE/admin/users?action=delete&id=5", "params": ["action", "id"]},
        {"method": "GET", "url": "BASE/admin/users?view=list&id=5", "params": ["view", "id"]},
    ]))
    .await;
    let acted: Vec<&String> = seen
        .iter()
        .filter(|l| l.contains("action=delete"))
        .collect();
    assert!(
        acted.is_empty(),
        "the action link was requested {} time(s): {acted:?}",
        acted.len()
    );
    assert!(
        seen.iter().any(|l| l.contains("/admin/users")),
        "the ordinary endpoint beside it was not probed either, so this proves nothing: {seen:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_password_change_link_never_carries_its_password_fields() {
    // DVWA's CSRF page: the new password travels in the query of a GET.
    let seen = run_pass(json!([
        {"method": "GET",
         "url": "BASE/vulnerabilities/csrf/?password_new=x1&password_conf=x1&Change=Change",
         "params": ["password_new", "password_conf", "Change"]},
    ]))
    .await;
    let carried: Vec<&String> = seen.iter().filter(|l| l.contains("password_new")).collect();
    assert!(
        carried.is_empty(),
        "a request carried the password field {} time(s): {carried:?}",
        carried.len()
    );
    assert!(
        seen.iter().any(|l| l.contains("/vulnerabilities/csrf/")),
        "the endpoint was not tested at all, so this proves nothing: {seen:?}"
    );
}

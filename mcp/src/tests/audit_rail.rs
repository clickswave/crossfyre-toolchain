//! One audit line per call, whatever happened, with the secrets masked; and no
//! traffic once the audit cannot be written.

use super::support::*;
use crate::audit::Audit;
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_call_leaves_exactly_one_masked_line() {
    let target = listener(Reply::ok("x")).await;
    let t = scope(&[format!("127.0.0.1:{}", target.port)], "").build();
    let peer = FakePeer::new(Elicit::None);
    let calls = [
        ("status", json!({})),
        (
            "send_http_request",
            json!({"method": "GET", "url": "http://elsewhere.test/"}),
        ),
        ("fingerprint", json!({"url": 7})),
        ("no_such_tool", json!({})),
        (
            "send_http_request",
            json!({
                "method": "GET",
                "url": format!("http://127.0.0.1:{}/a?token=abc123&page=2", target.port),
                "headers": {"Authorization": "Bearer sk-test-SECRET123", "X-Note": "fine"},
                "body": "body-secret-XYZ",
            }),
        ),
    ];
    for (tool, args) in &calls {
        t.call(&peer, tool, args.clone()).await;
    }
    let lines = t.audit_lines();
    assert_eq!(lines.len(), calls.len(), "{lines:#?}");
    let sha = t.mcp.scope.sha256.clone().unwrap();
    for (l, (tool, _)) in lines.iter().zip(calls.iter()) {
        assert_eq!(l["event"], "call");
        assert_eq!(l["tool"], *tool);
        assert_eq!(l["scope_sha256"], sha);
        assert_eq!(l["client"], "fake-client 1.0");
    }
    let decisions: Vec<&str> = lines
        .iter()
        .map(|l| l["decision"].as_str().unwrap())
        .collect();
    assert_eq!(decisions, ["ok", "refused", "error", "error", "ok"]);
    assert_eq!(lines[1]["reason"], "out_of_scope");
    assert_eq!(lines[1]["refused"][0]["host"], "elsewhere.test");
    assert_eq!(lines[2]["reason"], "invalid_arguments");
    assert_eq!(lines[3]["reason"], "unknown_tool");
    assert_eq!(lines[4]["args"]["body"]["body_bytes"], 15);
    assert_eq!(lines[4]["result"]["status"], 200);

    let text = t.audit_text();
    for secret in ["sk-test-SECRET123", "abc123", "body-secret-XYZ"] {
        assert!(!text.contains(secret), "{secret} reached the audit log");
    }
    assert!(text.contains("page=2") && text.contains("fine"));
    // The request itself carried them; only the record is masked.
    assert!(target.last_request().contains("sk-test-SECRET123"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_traffic_once_the_audit_cannot_be_written() {
    let target = listener(Reply::ok("x")).await;
    let t = scope(&[format!("127.0.0.1:{}", target.port)], "")
        .audit(|path| {
            std::fs::write(path, b"").unwrap();
            // Open for reading only, so every write fails as a full disk would.
            Audit::from_file(std::fs::File::open(path).unwrap(), path)
        })
        .build();
    let peer = FakePeer::new(Elicit::None);
    ok(&t.call(&peer, "status", json!({})).await);
    assert!(!t.mcp.audit.healthy());
    let r = t
        .call(
            &peer,
            "send_http_request",
            json!({"method": "GET", "url": format!("http://127.0.0.1:{}/", target.port)}),
        )
        .await;
    assert_eq!(reason(&r), "audit_unavailable");
    assert_eq!(target.conns(), 0);
    let s = ok(&t.call(&peer, "status", json!({})).await).clone();
    assert_eq!(s["audit"]["healthy"], false);
    ok(&t.call(&peer, "get_scope", json!({})).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oauth_style_secrets_are_masked_in_urls_and_messages() {
    let target = listener(Reply::ok("x")).await;
    let closed = closed_port();
    let t = scope(
        &[
            format!("127.0.0.1:{}", target.port),
            format!("127.0.0.1:{closed}"),
        ],
        "",
    )
    .build();
    let peer = FakePeer::new(Elicit::None);
    let calls = [
        (
            "send_http_request",
            json!({"method": "GET",
                   "url": format!("http://127.0.0.1:{closed}/?access_token=SECRETAAA1&refresh_token=SECRETAAA2")}),
        ),
        (
            "send_http_request",
            json!({"method": "GET",
                   "url": format!("http://127.0.0.1:{}/#access_token=SECRETBBB1&id_token=SECRETBBB2", target.port)}),
        ),
        (
            "fingerprint",
            json!({"url": format!("http://127.0.0.1:{}/#access_token=SECRETCCC1", target.port)}),
        ),
        (
            "send_http_request",
            json!({"method": "GET", "url": "http://evil.example/#client_secret=SECRETDDD1"}),
        ),
    ];
    for (tool, args) in &calls {
        t.call(&peer, tool, args.clone()).await;
    }
    assert_eq!(t.audit_lines().len(), calls.len());
    let text = t.audit_text();
    assert!(!text.contains("SECRET"), "{text}");
}

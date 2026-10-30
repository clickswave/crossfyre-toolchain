//! The Workbench tools: what is listed and when, and that every send passes both the
//! scope file and the open project's scope.

use super::support::*;
use crate::WorkbenchMode;
use serde_json::json;

#[tokio::test]
async fn a_workbench_tool_with_no_workbench_is_a_refusal_not_a_protocol_error() {
    let t = scope(&["app.example.test".into()], "").build();
    let r = t
        .call(
            &FakePeer::new(Elicit::None),
            "workbench_get_exchange",
            json!({"exchange": "wx_3f9a0c21be_1"}),
        )
        .await;
    assert!(!r.text.starts_with("protocol error"), "{}", r.text);
    assert_eq!(reason(&r), "workbench_unavailable", "{}", r.text);
    let line = t.audit_lines().pop().unwrap();
    assert_eq!(line["tool"], "workbench_get_exchange");
    assert_eq!(line["reason"], "workbench_unavailable");
    assert_eq!(line["decision"], "error");
}

#[tokio::test]
async fn the_mode_decides_what_is_listed_with_no_workbench() {
    let peer = FakePeer::new(Elicit::None);
    let listed = |t: &TestMcp| crate::server::tool_list(&t.mcp.backends()).len();

    let auto = scope(&["app.example.test".into()], "").build();
    assert_eq!(listed(&auto), 11);

    // For a client that never rereads the list: all seven, each refusing.
    let always = scope(&["app.example.test".into()], "")
        .workbench_mode(WorkbenchMode::Always)
        .build();
    assert_eq!(listed(&always), 18);
    let r = always
        .call(&peer, "workbench_list_history", json!({}))
        .await;
    assert_eq!(reason(&r), "workbench_unavailable", "{}", r.text);

    // Off: the names are not this server's at all.
    let off = scope(&["app.example.test".into()], "")
        .workbench_mode(WorkbenchMode::Off)
        .build();
    assert_eq!(listed(&off), 11);
    let r = off.call(&peer, "workbench_list_history", json!({})).await;
    assert!(r.text.starts_with("protocol error"), "{}", r.text);
}

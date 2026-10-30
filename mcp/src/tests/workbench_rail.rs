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

// ---------------------------------------------------------------------------
// Discovery and listing

#[cfg(unix)]
mod discovery {
    use super::*;
    use crate::tests::fake_wb::*;
    use cfx_bridge::Method;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn listed(t: &TestMcp) -> usize {
        crate::server::tool_list(&t.mcp.backends()).len()
    }

    async fn status_wb(t: &TestMcp) -> (serde_json::Value, Vec<String>) {
        let r = t
            .call(&FakePeer::new(Elicit::None), "status", json!({}))
            .await;
        let v = ok(&r).clone();
        let hints = v["hints"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h.as_str().unwrap().to_string())
            .collect();
        (v["workbench"].clone(), hints)
    }

    #[tokio::test]
    async fn no_control_directory_means_no_workbench_tools() {
        let wb = TempDir::new();
        let t = scope(&["app.example.test".into()], "")
            .workbench_dir(wb.path())
            .build();
        t.mcp.workbench.refresh().await;
        assert_eq!(listed(&t), 11);
        let (w, _) = status_wb(&t).await;
        assert_eq!(w["mode"], "auto");
        assert_eq!(w["instances"], json!([]));
        assert_eq!(w["ignored"], json!([]));
    }

    #[tokio::test]
    async fn the_tools_come_and_go_with_the_workbench() {
        let wb = TempDir::new();
        let t = scope(&["app.example.test".into()], "")
            .workbench_dir(wb.path())
            .build();
        let mut fake = FakeWb::start(wb.path(), WbOpts::default()).await;
        t.mcp.workbench.refresh().await;
        assert_eq!(listed(&t), 18);
        assert_eq!(fake.welcomed(), 1);

        let (w, _) = status_wb(&t).await;
        let i = &w["instances"][0];
        assert_eq!(i["pid"], fake.pid);
        assert_eq!(i["agent_access"], true);
        assert_eq!(i["project"], "acme-q4");
        assert_eq!(i["project_uid"], UID_A);
        assert_eq!(i["project_scope"]["restricted"], false);
        assert_eq!(fake.count(Method::Status), 1);
        assert_eq!(fake.requests()[0].params, serde_json::Value::Null);

        fake.exit();
        let mcp = Arc::clone(&t.mcp);
        eventually("the tools to go", 5, || {
            crate::server::tool_list(&mcp.backends()).len() == 11
        })
        .await;
    }

    #[tokio::test]
    async fn a_missing_capability_hides_only_the_tools_that_need_it() {
        let wb = TempDir::new();
        let t = scope(&["app.example.test".into()], "")
            .workbench_dir(wb.path())
            .build();
        let _fake = FakeWb::start(wb.path(), WbOpts::default().without(Method::Replay)).await;
        t.mcp.workbench.refresh().await;
        let names: Vec<String> = crate::server::tool_list(&t.mcp.backends())
            .iter()
            .map(|t| t.name.to_string())
            .collect();
        assert_eq!(names.len(), 17);
        assert!(!names.contains(&"workbench_replay".to_string()));
        assert!(names.contains(&"workbench_get_exchange".to_string()));
    }

    #[tokio::test]
    async fn an_endpoint_file_others_can_read_is_ignored_and_reported() {
        let wb = TempDir::new();
        let t = scope(&["app.example.test".into()], "")
            .workbench_dir(wb.path())
            .build();
        let fake = FakeWb::start(
            wb.path(),
            WbOpts {
                file_mode: 0o644,
                ..WbOpts::default()
            },
        )
        .await;
        t.mcp.workbench.refresh().await;
        assert_eq!(listed(&t), 11);
        assert_eq!(fake.hellos(), 0, "the socket was not even tried");
        let (w, hints) = status_wb(&t).await;
        assert_eq!(w["instances"], json!([]));
        assert_eq!(w["ignored"][0]["file"], format!("{}.json", fake.pid));
        let why = w["ignored"][0]["why"].as_str().unwrap();
        assert!(why.contains("other users"), "{why}");
        assert!(hints.iter().any(|h| h.contains("workbench.ignored")));
    }

    #[tokio::test]
    async fn a_socket_outside_the_workbench_directories_is_ignored() {
        let wb = TempDir::new();
        let elsewhere = TempDir::new();
        let t = scope(&["app.example.test".into()], "")
            .workbench_dir(wb.path())
            .build();
        let fake = FakeWb::start(
            wb.path(),
            WbOpts {
                socket: Some(elsewhere.path().join("wb.sock")),
                ..WbOpts::default()
            },
        )
        .await;
        t.mcp.workbench.refresh().await;
        assert_eq!(listed(&t), 11);
        assert_eq!(fake.hellos(), 0);
        let ignored = t.mcp.workbench.ignored();
        assert_eq!(ignored.len(), 1);
        assert!(ignored[0].why.contains("outside"), "{:?}", ignored[0]);
    }

    #[tokio::test]
    async fn a_wrong_token_gets_no_welcome_and_no_tools() {
        let wb = TempDir::new();
        let t = scope(&["app.example.test".into()], "")
            .workbench_dir(wb.path())
            .build();
        let fake = FakeWb::start(
            wb.path(),
            WbOpts {
                file_token: Some("ab".repeat(32)),
                ..WbOpts::default()
            },
        )
        .await;
        t.mcp.workbench.refresh().await;
        assert_eq!(listed(&t), 11);
        assert_eq!(fake.hellos(), 1);
        assert_eq!(fake.welcomed(), 0);
        let ignored = t.mcp.workbench.ignored();
        assert!(ignored[0].why.contains("without a welcome"), "{ignored:?}");
    }

    #[tokio::test]
    async fn a_workbench_with_access_off_is_named_with_the_switch_to_flip() {
        let wb = TempDir::new();
        let t = scope(&["app.example.test".into()], "")
            .workbench_dir(wb.path())
            .build();
        access_off(wb.path(), std::process::id());
        let (w, hints) = status_wb(&t).await;
        assert_eq!(w["instances"][0]["agent_access"], false);
        assert!(
            hints
                .iter()
                .any(|h| h.contains("Agent access is off") && h.contains("Agents chip")),
            "{hints:?}"
        );
        assert_eq!(listed(&t), 11);
    }

    #[tokio::test]
    async fn a_file_left_by_a_crash_is_passed_over() {
        let wb = TempDir::new();
        let t = scope(&["app.example.test".into()], "")
            .workbench_dir(wb.path())
            .build();
        let mut gone = std::process::Command::new("true").spawn().unwrap();
        let pid = gone.id();
        gone.wait().unwrap();
        access_off(wb.path(), pid);
        let (w, _) = status_wb(&t).await;
        assert_eq!(w["instances"], json!([]));
        assert_eq!(w["ignored"], json!([]));
    }

    #[tokio::test]
    async fn off_never_looks() {
        let wb = TempDir::new();
        let t = scope(&["app.example.test".into()], "")
            .workbench_dir(wb.path())
            .workbench_mode(WorkbenchMode::Off)
            .build();
        let fake = FakeWb::start(wb.path(), WbOpts::default()).await;
        t.mcp.workbench.refresh().await;
        let (w, _) = status_wb(&t).await;
        assert_eq!(w["mode"], "off");
        assert_eq!(w["instances"], json!([]));
        assert_eq!(fake.hellos(), 0);
    }

    #[tokio::test]
    async fn the_client_is_told_when_the_list_changes() {
        let wb = TempDir::new();
        let t = scope(&["app.example.test".into()], "")
            .workbench_dir(wb.path())
            .build();
        let told = Arc::new(AtomicUsize::new(0));
        let n = Arc::clone(&told);
        let watcher = tokio::spawn(crate::workbench::watch(
            Arc::clone(&t.mcp),
            move || -> crate::guard::BoxFut<'static, ()> {
                n.fetch_add(1, Ordering::SeqCst);
                Box::pin(async {})
            },
        ));
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert_eq!(told.load(Ordering::SeqCst), 0, "nothing changed yet");

        let mut fake = FakeWb::start(wb.path(), WbOpts::default()).await;
        eventually("a list_changed for the new Workbench", 5, || {
            told.load(Ordering::SeqCst) == 1
        })
        .await;
        fake.exit();
        eventually("a list_changed for the Workbench going", 5, || {
            told.load(Ordering::SeqCst) == 2
        })
        .await;
        watcher.abort();
    }
}

#[cfg(unix)]
mod instances {
    use super::*;
    use crate::tests::fake_wb::*;
    use cfx_bridge::{ErrorBody, ErrorCode, Method};

    async fn status(t: &TestMcp) -> serde_json::Value {
        let r = t
            .call(&FakePeer::new(Elicit::None), "status", json!({}))
            .await;
        ok(&r).clone()
    }

    #[tokio::test]
    async fn two_workbenches_are_both_reported_with_their_projects() {
        let wb = TempDir::new();
        let t = scope(&["app.example.test".into()], "")
            .workbench_dir(wb.path())
            .build();
        let _a = FakeWb::start(wb.path(), WbOpts::default()).await;
        let _b = FakeWb::start(
            wb.path(),
            WbOpts::default()
                .pid(OTHER_PID)
                .project(Some(project(UID_B, "beta"))),
        )
        .await;
        let v = status(&t).await;
        let mut seen: Vec<(u64, String)> = v["workbench"]["instances"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| {
                (
                    i["pid"].as_u64().unwrap(),
                    i["project"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        seen.sort();
        assert_eq!(
            seen,
            [
                (u64::from(OTHER_PID), "beta".to_string()),
                (u64::from(std::process::id()), "acme-q4".to_string())
            ]
        );
    }

    #[tokio::test]
    async fn a_closed_project_is_said_in_status() {
        let wb = TempDir::new();
        let t = scope(&["app.example.test".into()], "")
            .workbench_dir(wb.path())
            .build();
        let fake = FakeWb::start(wb.path(), WbOpts::default()).await;
        t.mcp.workbench.refresh().await;
        fake.switch(None);
        let v = status(&t).await;
        assert_eq!(v["workbench"]["instances"][0]["project"], json!(null));
        assert!(
            v["hints"].to_string().contains("has no project open"),
            "{}",
            v["hints"]
        );
    }

    #[tokio::test]
    async fn a_workbench_that_cannot_say_how_it_stands_is_still_listed_with_why() {
        let wb = TempDir::new();
        let t = scope(&["app.example.test".into()], "")
            .workbench_dir(wb.path())
            .build();
        let _fake = FakeWb::start(
            wb.path(),
            WbOpts::default().answer(Method::Status, |_, _| {
                Err(ErrorBody::new(
                    ErrorCode::Internal,
                    "\u{1b}[31mstore locked",
                ))
            }),
        )
        .await;
        let v = status(&t).await;
        let i = &v["workbench"]["instances"][0];
        assert_eq!(i["project"], "acme-q4", "from the welcome");
        let why = i["status_error"].as_str().unwrap();
        assert!(
            why.contains("store locked") && !why.contains('\u{1b}'),
            "{why}"
        );
    }
}

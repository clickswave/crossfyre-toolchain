//! The job store: paging without gaps or repeats, following a running scan, finding
//! scans their server abandoned, and ids that are not paths.

use super::support::*;
use crate::findings::{self, Stamp};
use crate::jobs::{self, JobMeta, JobStore, NewJob};
use serde_json::{Value, json};
use std::collections::HashSet;

fn job(store: &JobStore, session: &str) -> JobMeta {
    let m = JobMeta::new(
        session,
        NewJob {
            tool: "test_injection",
            engine: "plessor",
            target: "http://a.test",
            endpoints: Vec::new(),
            scope_sha256: None,
            cancellable: true,
            test_writes: false,
        },
    );
    store.write_meta(&m).unwrap();
    m
}

fn add(store: &JobStore, scan: &str, from: u64, n: u64, at: i64) {
    let fs: Vec<Value> = (from..from + n)
        .map(|i| {
            findings::from_plessor(
                &json!({"vuln_class": "xss", "name": format!("f{i}"), "severity": "low",
                        "description": "d", "url": "http://a.test/?q=1"}),
                Stamp {
                    id: jobs::new_id("f"),
                    scan_id: scan,
                    seq: i,
                    recorded_ms: at,
                },
            )
        })
        .collect();
    store.append_findings(scan, &fs).unwrap();
}

#[tokio::test]
async fn five_hundred_findings_page_out_with_no_repeats_and_then_only_newer_ones() {
    let t = scope(&["a.test".into()], "").build();
    let a = job(&t.mcp.jobs, &t.mcp.session);
    let b = job(&t.mcp.jobs, &t.mcp.session);
    // Two scans, interleaved in time, with ties on the timestamp.
    for k in 0..25u64 {
        add(&t.mcp.jobs, &a.id, k * 10 + 1, 10, 1_000 + k as i64);
        add(&t.mcp.jobs, &b.id, k * 10 + 1, 10, 1_000 + k as i64);
    }
    let peer = FakePeer::new(Elicit::None);
    let mut seen = HashSet::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0;
    loop {
        let mut args = json!({"limit": 50});
        if let Some(c) = &cursor {
            args["cursor"] = json!(c);
        }
        let v = ok(&t.call(&peer, "list_findings", args).await).clone();
        pages += 1;
        for f in v["findings"].as_array().unwrap() {
            assert!(
                seen.insert(f["id"].as_str().unwrap().to_string()),
                "repeated"
            );
        }
        cursor = Some(v["next_cursor"].as_str().unwrap().to_string());
        if v["more"] == false {
            break;
        }
        assert!(pages < 20);
    }
    assert_eq!(seen.len(), 500);
    assert_eq!(pages, 10);

    // Polling with the last cursor returns only what was recorded since.
    let v = ok(&t
        .call(
            &peer,
            "list_findings",
            json!({"cursor": cursor.clone().unwrap()}),
        )
        .await)
    .clone();
    assert_eq!(v["findings"].as_array().unwrap().len(), 0);
    assert_eq!(
        v["next_cursor"],
        json!(cursor.clone().unwrap()),
        "an empty page keeps its place"
    );
    add(&t.mcp.jobs, &a.id, 1000, 3, jobs::now_ms());
    let v = ok(&t
        .call(&peer, "list_findings", json!({"cursor": cursor.unwrap()}))
        .await)
    .clone();
    let names: Vec<&str> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["f1000", "f1001", "f1002"]);

    // And one scan's findings alone, at or above a severity.
    let v = ok(&t
        .call(
            &peer,
            "list_findings",
            json!({"scan_id": b.id, "severity_min": "medium"}),
        )
        .await)
    .clone();
    assert_eq!(v["findings"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn a_running_scan_whose_server_went_quiet_becomes_interrupted() {
    let dir = TempDir::new();
    let store = JobStore::open(dir.path()).unwrap();
    let mut stale = job(&store, "m_otherserver");
    stale.updated_ms -= 10 * 60 * 1000;
    store.write_meta(&stale).unwrap();
    let fresh = job(&store, "m_otherserver");
    let done = {
        let mut m = job(&store, "m_otherserver");
        m.finish(jobs::COMPLETED);
        store.write_meta(&m).unwrap();
        m
    };
    assert_eq!(store.recover("m_thisserver", jobs::now_ms()), 1);
    assert_eq!(
        store.read_meta(&stale.id).unwrap().status,
        jobs::INTERRUPTED
    );
    assert_eq!(store.read_meta(&fresh.id).unwrap().status, jobs::RUNNING);
    assert_eq!(store.read_meta(&done.id).unwrap().status, jobs::COMPLETED);
}

#[tokio::test]
async fn ids_that_look_like_paths_are_refused() {
    let t = scope(&["a.test".into()], "").build();
    let peer = FakePeer::new(Elicit::None);
    for (tool, args) in [
        ("get_scan", json!({"scan_id": "../x"})),
        ("get_scan", json!({"scan_id": "s_ZZ"})),
        ("get_scan", json!({"scan_id": "s_0123456789/../../a"})),
        ("cancel_scan", json!({"scan_id": "../../etc/passwd"})),
        ("list_findings", json!({"scan_id": "..\\x"})),
        ("get_finding", json!({"finding_id": "f_../../a"})),
        ("list_findings", json!({"cursor": "../x"})),
        ("list_scans", json!({"cursor": "1-../x"})),
    ] {
        let r = t.call(&peer, tool, args.clone()).await;
        assert_eq!(reason(&r), "invalid_arguments", "{tool} {args}");
    }
    let r = t
        .call(&peer, "get_scan", json!({"scan_id": "s_0123456789"}))
        .await;
    assert_eq!(reason(&r), "not_found");
}

#[tokio::test]
async fn old_finished_jobs_are_pruned_and_running_ones_kept() {
    let dir = TempDir::new();
    let store = JobStore::open(dir.path()).unwrap();
    let running = job(&store, "m_a");
    let mut ids = Vec::new();
    for i in 0..5 {
        let mut m = job(&store, "m_a");
        m.created_ms += i;
        m.finish(jobs::COMPLETED);
        store.write_meta(&m).unwrap();
        ids.push(m.id);
    }
    store.prune(2);
    let left: HashSet<String> = store.list().into_iter().map(|m| m.id).collect();
    assert!(left.contains(&running.id));
    assert_eq!(left.len(), 3, "{left:?}");
    assert!(left.contains(&ids[4]) && left.contains(&ids[3]));
}

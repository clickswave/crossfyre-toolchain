//! Scans and findings as the engines keep them: paging without gaps or repeats, following
//! a running scan, only what is inside the loaded scope, and ids that are not paths.

use super::support::*;
use serde_json::{Value, json};
use std::collections::HashSet;

fn finding(i: u64, severity: &str) -> Value {
    json!({"vuln_class": "xss", "name": format!("f{i}"), "severity": severity,
           "description": "d", "url": "http://a.test/?q=1"})
}

/// The time `n` seconds into a day, as an engine says it.
fn at(n: u64) -> String {
    format!(
        "2026-11-21T{:02}:{:02}:{:02}Z",
        n / 3600,
        n / 60 % 60,
        n % 60
    )
}

#[tokio::test]
async fn five_hundred_findings_page_out_with_no_repeats_and_then_only_newer_ones() {
    let plessor = stub_engine(StubOpts::default()).await;
    let toolmark = stub_engine(StubOpts::default()).await;
    let (a, b) = {
        let mut p = plessor.kept.lock().unwrap();
        let mut t = toolmark.kept.lock().unwrap();
        (
            p.scan("http://a.test", "completed", json!({}), &at(1)),
            t.scan("http://a.test", "completed", json!({}), &at(2)),
        )
    };
    // Two engines' scans, interleaved in time, with ties on the time.
    for k in 0..25u64 {
        for i in 0..10 {
            let n = k * 10 + i + 1;
            plessor
                .kept
                .lock()
                .unwrap()
                .finding(&a, finding(n, "low"), &at(1000 + k));
            toolmark.kept.lock().unwrap().finding(
                &b,
                json!({"type": "technology", "name": format!("t{n}"), "target": "http://a.test"}),
                &at(1000 + k),
            );
        }
    }
    let t = scope(&["a.test".into()], "")
        .plessor(plessor.port)
        .toolmark(toolmark.port)
        .build();
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

    // Following with the last cursor gives only what was kept since.
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
    for n in 1000..1003 {
        plessor
            .kept
            .lock()
            .unwrap()
            .finding(&a, finding(n, "low"), &at(5000));
    }
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
            json!({"scan_id": format!("s_plessor_{a}"), "severity_min": "medium"}),
        )
        .await)
    .clone();
    assert_eq!(v["findings"].as_array().unwrap().len(), 0);
}

/// A scan made from the command line of a target in the scope file is listed, with what
/// it found; one of a target outside it is not, nor is what it found, and its id is
/// answered as if there were none.
#[tokio::test]
async fn only_scans_inside_the_scope_file_are_shown_from_any_source() {
    let plessor = stub_engine(StubOpts::default()).await;
    let (inside, outside) = {
        let mut p = plessor.kept.lock().unwrap();
        let inside = p.scan(
            "http://a.test",
            "completed",
            json!({"operation": "scan"}),
            &at(1),
        );
        let outside = p.scan(
            "http://other.test",
            "completed",
            json!({"operation": "scan"}),
            &at(2),
        );
        p.finding(&inside, finding(1, "high"), &at(3));
        p.finding(&outside, finding(2, "high"), &at(4));
        (inside, outside)
    };
    let t = scope(&["a.test".into()], "").plessor(plessor.port).build();
    let peer = FakePeer::new(Elicit::None);
    let listed = ok(&t.call(&peer, "list_scans", json!({})).await).clone();
    let ids: Vec<&str> = listed["scans"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["scan_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, [format!("s_plessor_{inside}")]);
    assert_eq!(listed["scans"][0]["tool"], "plessor scan");
    assert_eq!(listed["scans"][0]["counts"]["findings"], 1);
    let found = ok(&t.call(&peer, "list_findings", json!({})).await).clone();
    let names: Vec<&str> = found["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["f1"]);
    let away = format!("s_plessor_{outside}");
    for (tool, args) in [
        ("get_scan", json!({"scan_id": away})),
        ("list_findings", json!({"scan_id": away})),
        ("get_finding", json!({"finding_id": "f_plessor_2"})),
    ] {
        let r = t.call(&peer, tool, args.clone()).await;
        assert_eq!(reason(&r), "not_found", "{tool} {args}");
    }
    let got = ok(&t
        .call(&peer, "get_finding", json!({"finding_id": "f_plessor_1"}))
        .await)
    .clone();
    assert_eq!(got["name"], "f1");
}

#[tokio::test]
async fn ids_that_look_like_paths_are_refused() {
    let t = scope(&["a.test".into()], "").build();
    let peer = FakePeer::new(Elicit::None);
    for (tool, args) in [
        ("get_scan", json!({"scan_id": "../x"})),
        ("get_scan", json!({"scan_id": "s_ZZ"})),
        (
            "get_scan",
            json!({"scan_id": "s_plessor_0123456789/../../a"}),
        ),
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
        .call(
            &peer,
            "get_scan",
            json!({"scan_id": "s_plessor_01234567-89ab-cdef-0123-456789abcdef"}),
        )
        .await;
    assert_eq!(reason(&r), "not_found");
}

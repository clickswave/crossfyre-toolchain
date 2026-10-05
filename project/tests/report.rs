//! The report is assembled from the store, and says what it does not have.
//!
//! Rendered here rather than in a window because the window is handed bounded, lossy
//! previews of bodies: a report built from those would quietly contain a truncated request
//! as the proof of a finding.

use cfx_project::report::{self, Meta};
use cfx_project::{Cap, Exchange, Finding, Project, Severity};
use std::path::{Path, PathBuf};

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "cfx-report-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn exchange(body: Vec<u8>) -> Exchange {
    Exchange {
        at_ms: 1_700_000_000_000,
        method: "GET".into(),
        url: "https://api.acme.test/v1/vehicles/42/location".into(),
        host: "api.acme.test".into(),
        status: Some(200),
        duration_ms: Some(11),
        req_headers: vec![["Authorization".into(), "Bearer alice".into()]],
        resp_headers: vec![["Content-Type".into(), "application/json".into()]],
        req_body: Vec::new(),
        resp_body: body,
        resp_len: None,
        ..Default::default()
    }
}

#[tokio::test]
async fn a_report_leads_with_the_worst_and_shows_what_proves_it() {
    let s = Scratch::new("basic");
    let p = Project::open(s.path(), Cap::default()).await.expect("open");
    let id = p
        .insert(&exchange(br#"{"lat":12.9,"lon":77.6}"#.to_vec()))
        .await
        .expect("insert");

    p.add_finding(&Finding {
        at_ms: 1_700_000_000_000,
        title: "Vehicle location is readable by any authenticated user".into(),
        severity: Severity::Critical,
        affected: "GET /v1/vehicles/{id}/location".into(),
        description: "Alice's token returns Bob's vehicle.".into(),
        repro: "Send the request below with Alice's token.".into(),
        remediation: "Check the vehicle belongs to the caller.".into(),
        evidence: vec![id],
        ..Default::default()
    })
    .await
    .expect("finding");
    p.add_finding(&Finding {
        at_ms: 1_700_000_000_000,
        title: "Server header discloses the version".into(),
        severity: Severity::Low,
        ..Default::default()
    })
    .await
    .expect("finding");

    let md = report::markdown(
        &p,
        &Meta {
            title: "Acme API assessment".into(),
            prepared_for: "Acme Ltd".into(),
            prepared_on: "2026-10-05".into(),
            summary: "Two findings.".into(),
        },
    )
    .await
    .expect("render");

    assert!(md.starts_with("# Acme API assessment\n"), "got:\n{md}");
    assert!(md.contains("Prepared for Acme Ltd"));

    // Worst first, which is the order a report leads with.
    let crit = md.find("Vehicle location").expect("critical is present");
    let low = md.find("Server header").expect("low is present");
    assert!(crit < low, "the critical finding comes first:\n{md}");

    // The counts table lists every severity, including the zeroes: a table of only what
    // was found reads as a table of what was looked for.
    assert!(md.contains("| Critical | 1 |"), "got:\n{md}");
    assert!(md.contains("| High | 0 |"), "got:\n{md}");

    // And the evidence is the real request and response, not a description of them.
    assert!(md.contains("Authorization: Bearer alice"), "got:\n{md}");
    assert!(md.contains(r#"{"lat":12.9,"lon":77.6}"#), "got:\n{md}");
    assert!(md.contains("### Remediation"), "got:\n{md}");

    // A finding with nothing behind it says so rather than looking the same as one that
    // simply has its evidence further down the page.
    assert!(
        md.contains("None recorded against this finding."),
        "got:\n{md}"
    );
}

#[tokio::test]
async fn an_empty_project_says_so_rather_than_rendering_a_blank_page() {
    let s = Scratch::new("empty");
    let p = Project::open(s.path(), Cap::default()).await.expect("open");
    let md = report::markdown(&p, &Meta::default())
        .await
        .expect("render");
    assert!(md.contains("No findings have been recorded"), "got:\n{md}");
    assert!(
        md.contains("not the same as a target with nothing wrong"),
        "and does not let an unwritten report read as a clean bill of health:\n{md}"
    );
}

/// A response containing a fence does not end the block early.
///
/// Otherwise the rest of the evidence renders as prose, which is a report silently
/// reformatting the thing it exists to show.
#[tokio::test]
async fn evidence_containing_a_code_fence_stays_inside_its_block() {
    let s = Scratch::new("fence");
    let p = Project::open(s.path(), Cap::default()).await.expect("open");
    let id = p
        .insert(&exchange(
            b"here is ``` a fence and ```` a longer one".to_vec(),
        ))
        .await
        .expect("insert");
    p.add_finding(&Finding {
        title: "t".into(),
        severity: Severity::Medium,
        evidence: vec![id],
        ..Default::default()
    })
    .await
    .expect("finding");

    let md = report::markdown(&p, &Meta::default())
        .await
        .expect("render");
    // The opening fence has to be longer than the longest run inside, which is four.
    assert!(md.contains("`````http"), "got:\n{md}");
}

/// A body that is not text is named rather than quoted.
#[tokio::test]
async fn a_binary_body_is_described_instead_of_pasted() {
    let s = Scratch::new("binary");
    let p = Project::open(s.path(), Cap::default()).await.expect("open");
    let mut png = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    png.extend_from_slice(&[0u8; 200]);
    let id = p.insert(&exchange(png.clone())).await.expect("insert");
    p.add_finding(&Finding {
        title: "t".into(),
        severity: Severity::Info,
        evidence: vec![id],
        ..Default::default()
    })
    .await
    .expect("finding");

    let md = report::markdown(&p, &Meta::default())
        .await
        .expect("render");
    assert!(
        md.contains(&format!("[{} bytes, not text]", png.len())),
        "got:\n{md}"
    );
}

/// A long body is cut, and the report says where.
#[tokio::test]
async fn a_long_body_is_cut_and_says_so() {
    let s = Scratch::new("long");
    let p = Project::open(s.path(), Cap::default()).await.expect("open");
    let big = "x".repeat(20_000).into_bytes();
    let id = p.insert(&exchange(big)).await.expect("insert");
    p.add_finding(&Finding {
        title: "t".into(),
        severity: Severity::Info,
        evidence: vec![id],
        ..Default::default()
    })
    .await
    .expect("finding");

    let md = report::markdown(&p, &Meta::default())
        .await
        .expect("render");
    assert!(
        md.contains("[cut here:"),
        "got the tail:\n{}",
        &md[md.len() - 400..]
    );
    assert!(
        md.contains("of 20000 bytes shown"),
        "and says how much there was"
    );
}

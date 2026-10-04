//! What this costs, measured rather than asserted.
//!
//! The plan carries four scale targets for the desktop window: a quarter of a million
//! exchanges in one project, search under 300ms, open under two seconds, memory under
//! 500MB. They were written as targets by somebody who had not measured any of them,
//! which is the same move as claiming a scanner's precision without a benchmark. The
//! scanner has one. This is the other one.
//!
//! Ignored by default, because these take seconds to minutes and a test suite that takes
//! minutes stops being run:
//!
//!     cargo test -p cfx_session --test measured -- --ignored --nocapture
//!
//! The numbers it prints are the ones to publish. If a target is not met, the honest move
//! is to publish the number that was: a measured worse number is worth more than an
//! unmeasured better one.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use cfx_capture::generate_ca;
use cfx_project::{Cap, Exchange, Project};
use cfx_session::testing::{eventually, ok_response, through_proxy, tls_origin};
use cfx_session::{Session, SessionConfig};

struct Scratch(std::path::PathBuf);
impl Scratch {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!("cfx-measured-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        Self(p)
    }
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn dir_bytes(p: &std::path::Path) -> u64 {
    let mut total = 0;
    if let Ok(rd) = std::fs::read_dir(p) {
        for e in rd.flatten() {
            let meta = match e.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            total += if meta.is_dir() {
                dir_bytes(&e.path())
            } else {
                meta.len()
            };
        }
    }
    total
}

/// Resident set in bytes, from the kernel. Not a Rust allocator figure: what matters is
/// what the operating system thinks this process is holding, because that is what runs a
/// laptop out of memory.
fn rss_bytes() -> u64 {
    std::fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|s| s.split_whitespace().nth(1).map(str::to_string))
        .and_then(|pages| pages.parse::<u64>().ok())
        .map(|pages| pages * 4096)
        .unwrap_or(0)
}

fn exchange(i: usize) -> Exchange {
    Exchange {
        at_ms: 1_700_000_000_000 + i as i64,
        method: "GET".into(),
        url: format!("https://api.acme.test/v1/users/{i}/orders?page={}", i % 7),
        host: "api.acme.test".into(),
        status: Some(200),
        duration_ms: Some(12),
        req_headers: vec![
            ["host".into(), "api.acme.test".into()],
            ["user-agent".into(), "crossfyre-measured".into()],
            ["accept".into(), "application/json".into()],
        ],
        resp_headers: vec![
            ["content-type".into(), "application/json".into()],
            ["x-request-id".into(), format!("req-{i}")],
        ],
        req_body: Vec::new(),
        resp_body: format!(
            "{{\"id\":{i},\"sku\":\"WIDGET-{i}\",\"note\":\"{}\"}}",
            "lorem ipsum dolor sit amet ".repeat(8)
        )
        .into_bytes(),
    }
}

#[tokio::test]
#[ignore = "measurement, not a gate: cargo test -- --ignored --nocapture"]
async fn what_the_project_store_costs() {
    // How many is deliberately below the quarter-million target: this has to finish in a
    // reasonable time on a laptop, and the per-exchange costs extrapolate. The open and
    // search figures are the ones that do not extrapolate, so they are measured on what
    // was actually written.
    const N: usize = 20_000;

    let s = Scratch::new("store");
    let before = rss_bytes();
    let t0 = Instant::now();
    {
        let p = Project::open(s.path(), Cap::default()).await.expect("open");
        let run = p.begin_run(1_700_000_000_000, Some("measured")).await.ok();
        for i in 0..N {
            p.insert(&exchange(i)).await.expect("insert");
        }
        let _ = run;
        let write = t0.elapsed();
        println!(
            "  write        {N} exchanges in {:?}  ({:.0}/s, {:.2}ms each)",
            write,
            N as f64 / write.as_secs_f64(),
            write.as_secs_f64() * 1000.0 / N as f64
        );
        p.close().await;
    }

    let on_disk = dir_bytes(s.path());
    println!(
        "  on disk      {:.1} MB for {N} exchanges  ({:.0} bytes each)",
        on_disk as f64 / 1e6,
        on_disk as f64 / N as f64
    );

    let t = Instant::now();
    let p = Project::open(s.path(), Cap::default())
        .await
        .expect("reopen");
    let open = t.elapsed();
    println!("  open         {open:?}   (target: under 2s)");

    let t = Instant::now();
    let hits = p.search("WIDGET-19999", 50).await.expect("search");
    let search_rare = t.elapsed();
    let t = Instant::now();
    let common = p.search("lorem", 50).await.expect("search");
    let search_common = t.elapsed();
    println!(
        "  search       rare term {search_rare:?} ({} hits), common term {search_common:?} ({} hits)   (target: under 300ms)",
        hits.len(),
        common.len()
    );

    let t = Instant::now();
    let rows = p.recent(500).await.expect("recent");
    println!(
        "  history page {:?} for {} rows   (what the window asks for on every poll)",
        t.elapsed(),
        rows.len()
    );

    let after = rss_bytes();
    println!(
        "  memory       {:.0} MB resident, {:+.0} MB over the start   (target: under 500MB)",
        after as f64 / 1e6,
        (after as f64 - before as f64) / 1e6
    );

    // Extrapolated, and labelled as extrapolated.
    println!(
        "  at 250k      about {:.0} MB on disk if it scales linearly",
        on_disk as f64 / N as f64 * 250_000.0 / 1e6
    );
}

#[tokio::test]
#[ignore = "measurement, not a gate: cargo test -- --ignored --nocapture"]
async fn what_a_large_response_costs_in_memory() {
    // The whole response body is collected before a byte reaches the client. That is
    // simple and it is what makes the exchange recordable, and it also means the proxy
    // holds the entire thing. A pentester downloading a backup, a video or a disk image
    // through here is the ordinary case, not a contrived one.
    //
    // This measures what one does to resident memory. The number matters more than the
    // ratio: an operator does not care that it is linear, they care whether their laptop
    // survives it.
    const MB: usize = 64;

    let s = Scratch::new("bigbody");
    let body = "x".repeat(MB * 1024 * 1024);
    let reply = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    )
    .into_bytes();
    drop(body);

    let (origin_port, _) = tls_origin(reply).await;
    let project = Arc::new(Project::open(s.path(), Cap::default()).await.expect("open"));
    let ca = Arc::new(generate_ca().expect("ca"));
    let ca_pem = ca.pem.clone();
    let mut cfg = SessionConfig::new(project.clone(), ca);
    cfg.trust_any_upstream_cert = true;
    let session = Session::start(cfg).await.expect("session");

    let before = rss_bytes();
    let t = Instant::now();
    let (status, got) = through_proxy(
        session.port(),
        origin_port,
        &ca_pem,
        "GET",
        "/backup.tar",
        Vec::new(),
    )
    .await;
    let took = t.elapsed();
    let peak = rss_bytes();
    assert_eq!(status, 200);
    assert_eq!(got.len(), MB * 1024 * 1024, "the whole body came through");

    println!(
        "  {MB} MB response in {took:?}  ({:.0} MB/s)",
        MB as f64 / took.as_secs_f64()
    );
    println!(
        "  memory       {:.0} MB resident before, {:.0} MB after  ({:+.0} MB for a {MB} MB body)",
        before as f64 / 1e6,
        peak as f64 / 1e6,
        (peak as f64 - before as f64) / 1e6
    );
    let ratio = (peak as f64 - before as f64) / (MB as f64 * 1e6);
    println!(
        "  that is about {ratio:.1}x the body size held at once. A one-gigabyte download \
         would therefore need roughly {:.1} GB.",
        ratio.max(1.0)
    );

    session.stop().await;
}

#[tokio::test]
#[ignore = "measurement, not a gate: cargo test -- --ignored --nocapture"]
async fn what_a_request_through_the_proxy_costs() {
    // The question underneath this one: every forwarded request currently dials a fresh
    // TCP connection and does a fresh TLS handshake, and a conformance test pins that.
    // Before adding a connection pool to a security tool, where a reuse bug means one
    // request's response reaching another, it is worth knowing what the handshake
    // actually costs. This measures it against a loopback origin, which is the FRIENDLIEST
    // possible case: on a real network each handshake also pays one or two round trips.
    const N: usize = 200;

    let s = Scratch::new("proxy");
    let (origin_port, handshakes) = tls_origin(ok_response("measured")).await;
    let project = Arc::new(Project::open(s.path(), Cap::default()).await.expect("open"));
    let ca = Arc::new(generate_ca().expect("ca"));
    let ca_pem = ca.pem.clone();
    let mut cfg = SessionConfig::new(project.clone(), ca);
    cfg.trust_any_upstream_cert = true;
    let session = Session::start(cfg).await.expect("session");

    // One first, so lazily-built TLS configuration is not counted in the batch.
    let _ = through_proxy(
        session.port(),
        origin_port,
        &ca_pem,
        "GET",
        "/warm",
        Vec::new(),
    )
    .await;
    let before = handshakes.load(Ordering::Relaxed);

    let t = Instant::now();
    for i in 0..N {
        let (status, _) = through_proxy(
            session.port(),
            origin_port,
            &ca_pem,
            "GET",
            &format!("/item/{i}"),
            Vec::new(),
        )
        .await;
        assert_eq!(status, 200);
    }
    let took = t.elapsed();
    let upstream = handshakes.load(Ordering::Relaxed) - before;

    println!(
        "  {N} requests in {took:?}  ({:.0}/s, {:.2}ms each)",
        N as f64 / took.as_secs_f64(),
        took.as_secs_f64() * 1000.0 / N as f64
    );
    println!(
        "  upstream TLS handshakes: {upstream} for {N} requests  ({:.2} per request)",
        upstream as f64 / N as f64
    );
    if upstream >= N {
        println!(
            "  every request pays a full handshake. On loopback that is cheap; across a \
             network it is one or two extra round trips per request."
        );
    }

    let p = project.clone();
    eventually("everything was recorded", || {
        let p = p.clone();
        async move { p.count().await.unwrap_or(0) as usize >= N }
    })
    .await;
    println!(
        "  recorded     {} exchanges",
        project.count().await.unwrap_or(0)
    );
    session.stop().await;
}

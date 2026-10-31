//! Ship captured events to the control plane. Batches privacy-safe [`TraceEvent`]s and POSTs them to
//! the same nodeless, workspace-scoped ingest endpoint the desktop tracer uses:
//! `POST {api_url}/api/v1/web-trace/ingest` with `{workflow_id, token, events, ended}`. The app itself
//! is excluded from the VPN, so this egress traffic is never re-captured. reqwest uses rustls (no
//! native-tls) so it cross-compiles to Android.
//!
//! A 401 means the server no longer takes the session's token: the session ended, or whoever armed
//! it was removed from the workspace or lost the role that lets them capture. No later batch under
//! that token can succeed, so from then on nothing is sent, and the app is told through
//! `token_refused` so it can stop and offer a new pairing.

use std::time::Duration;

use cfx_capture::TraceEvent;
use tokio::sync::mpsc::UnboundedReceiver;

const MAX_BATCH: usize = 50;
const FLUSH_EVERY: Duration = Duration::from_secs(2);

/// Drain events until the channel closes (capture stopped), flushing on size or a timer. Sends a
/// final `ended: true` batch so the server can close the trace session.
pub async fn run(
    mut rx: UnboundedReceiver<TraceEvent>,
    api_url: String,
    workflow_id: String,
    token: String,
) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .unwrap_or_default();
    let url = format!("{}/api/v1/web-trace/ingest", api_url.trim_end_matches('/'));
    let mut batch: Vec<TraceEvent> = Vec::new();
    // The sequence number of the newest event in `batch`, so a delivered batch can be marked sent
    // on the requests the Tracer screen lists.
    let mut last_seq = 0u64;
    let mut ticker = tokio::time::interval(FLUSH_EVERY);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // The server turned the token away. Events are still counted and kept for the screen, but
    // none is sent: under this token every batch would be turned away again.
    let mut refused = false;

    loop {
        tokio::select! {
            ev = rx.recv() => match ev {
                Some(e) => {
                    log::info!("event: {} {} ({:?})", e.method, e.url, e.status);
                    crate::stats::inc(&crate::stats::EVENTS);
                    crate::stats::set_last_event(format!("{} {}", e.method, e.url));
                    last_seq = crate::stats::record_event(&e);
                    if refused {
                        continue;
                    }
                    batch.push(e);
                    if batch.len() >= MAX_BATCH {
                        refused = flush(&client, &url, &workflow_id, &token, &mut batch, last_seq, false).await
                            == Shipped::Refused;
                    }
                }
                None => {
                    // Channel closed: capture stopped. Final flush closes the session, unless the
                    // server has already said the session is not one it takes.
                    if !refused {
                        flush(&client, &url, &workflow_id, &token, &mut batch, last_seq, true).await;
                    }
                    return;
                }
            },
            _ = ticker.tick() => {
                if !refused && !batch.is_empty() {
                    refused = flush(&client, &url, &workflow_id, &token, &mut batch, last_seq, false).await
                        == Shipped::Refused;
                }
            }
        }
    }
}

/// What became of one batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shipped {
    Delivered,
    /// Not delivered this time: kept, and sent again with the next batch.
    Kept,
    /// The server no longer takes the token. Dropped, and nothing more is sent.
    Refused,
}

async fn flush(
    client: &reqwest::Client,
    url: &str,
    workflow_id: &str,
    token: &str,
    batch: &mut Vec<TraceEvent>,
    last_seq: u64,
    ended: bool,
) -> Shipped {
    if batch.is_empty() && !ended {
        return Shipped::Delivered;
    }
    let payload = serde_json::json!({
        "workflow_id": workflow_id,
        "token": token,
        "events": &*batch,
        "ended": ended,
    });
    let n = batch.len() as u64;
    match client.post(url).json(&payload).send().await {
        Ok(res) if res.status().is_success() => {
            log::info!("ingested {} events (ended={ended})", batch.len());
            crate::stats::INGEST_SENT.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
            crate::stats::mark_sent(last_seq);
            batch.clear();
            Shipped::Delivered
        }
        Ok(res) if res.status() == reqwest::StatusCode::UNAUTHORIZED => {
            log::warn!("ingest refused the session token: HTTP 401; sending stops");
            crate::stats::inc(&crate::stats::INGEST_REJECTED);
            crate::stats::TOKEN_REFUSED.store(1, std::sync::atomic::Ordering::Relaxed);
            crate::stats::set_last_error(
                "the server no longer accepts this session's token (HTTP 401)".into(),
            );
            batch.clear();
            Shipped::Refused
        }
        Ok(res) => {
            log::warn!("ingest rejected: HTTP {}", res.status());
            crate::stats::inc(&crate::stats::INGEST_REJECTED);
            crate::stats::set_last_error(format!("server rejected ingest: HTTP {}", res.status()));
            Shipped::Kept
        }
        Err(e) => {
            log::warn!("ingest post failed: {e}");
            crate::stats::inc(&crate::stats::INGEST_FAILED);
            crate::stats::set_last_error(format!("ingest send failed: {e}"));
            Shipped::Kept
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn event(i: usize) -> TraceEvent {
        TraceEvent {
            method: "GET".into(),
            url: format!("https://api.example.test/r/{i}"),
            status: Some(200),
            ..Default::default()
        }
    }

    /// An ingest that turns every batch away as it does a token it no longer takes, and counts
    /// the requests it reads.
    async fn refusing() -> (String, Arc<AtomicUsize>) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let n = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&n);
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let seen = Arc::clone(&seen);
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 8192];
                    let body_at = loop {
                        let Ok(k) = s.read(&mut chunk).await else {
                            return;
                        };
                        if k == 0 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..k]);
                        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break i + 4;
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..body_at]).to_ascii_lowercase();
                    let len: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0);
                    while buf.len() < body_at + len {
                        let Ok(k) = s.read(&mut chunk).await else {
                            return;
                        };
                        if k == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..k]);
                    }
                    seen.fetch_add(1, Ordering::SeqCst);
                    let body = r#"{"status":401,"message":"Invalid session token","errors":[],"data":null}"#;
                    let reply = format!(
                        "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(reply.as_bytes()).await;
                });
            }
        });
        (url, n)
    }

    // The counters are process globals, so this holds the lock the other tests that touch them
    // hold. The runtime is this test's own, so nothing else on it waits for the lock.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn a_token_the_server_turned_away_is_not_sent_again() {
        let _held = crate::stats::TEST_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        crate::stats::reset();
        let (url, asked) = refusing().await;
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let shipper = tokio::spawn(run(rx, url, "wf-1".into(), "token-1".into()));
        let many = MAX_BATCH * 2 + 7;
        for i in 0..many {
            tx.send(event(i)).unwrap();
        }
        // Past the flush timer, so a batch left waiting would have gone out again by now.
        tokio::time::sleep(FLUSH_EVERY + Duration::from_millis(700)).await;
        for i in 0..5 {
            tx.send(event(many + i)).unwrap();
        }
        drop(tx);
        tokio::time::timeout(Duration::from_secs(20), shipper)
            .await
            .expect("the shipper ends when capture stops")
            .unwrap();
        // One batch, turned away, and nothing after it: not the next batch, not the timer's, and
        // not the closing one either.
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        let s: serde_json::Value = serde_json::from_str(&crate::stats::snapshot_json()).unwrap();
        assert_eq!(s["token_refused"], true, "{s}");
        assert_eq!(s["ingest_sent"], 0, "{s}");
        assert_eq!(s["ingest_rejected"], 1, "{s}");
        // Still counted as captured, so the phone can say what never left it.
        assert_eq!(s["events"], (many + 5) as u64, "{s}");
        assert!(s["last_error"].as_str().unwrap().contains("401"), "{s}");
        crate::stats::reset();
    }
}

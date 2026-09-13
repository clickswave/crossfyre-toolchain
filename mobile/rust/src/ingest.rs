//! Ship captured events to the control plane. Batches privacy-safe [`TraceEvent`]s and POSTs them to
//! the same nodeless, workspace-scoped ingest endpoint the desktop tracer uses:
//! `POST {api_url}/api/v1/web-trace/ingest` with `{workflow_id, token, events, ended}`. The app itself
//! is excluded from the VPN, so this egress traffic is never re-captured. reqwest uses rustls (no
//! native-tls) so it cross-compiles to Android.

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
    let mut ticker = tokio::time::interval(FLUSH_EVERY);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            ev = rx.recv() => match ev {
                Some(e) => {
                    log::info!("event: {} {} ({:?})", e.method, e.url, e.status);
                    crate::stats::inc(&crate::stats::EVENTS);
                    crate::stats::set_last_event(format!("{} {}", e.method, e.url));
                    batch.push(e);
                    if batch.len() >= MAX_BATCH {
                        flush(&client, &url, &workflow_id, &token, &mut batch, false).await;
                    }
                }
                None => {
                    // Channel closed: capture stopped. Final flush closes the session.
                    flush(&client, &url, &workflow_id, &token, &mut batch, true).await;
                    return;
                }
            },
            _ = ticker.tick() => {
                if !batch.is_empty() {
                    flush(&client, &url, &workflow_id, &token, &mut batch, false).await;
                }
            }
        }
    }
}

async fn flush(
    client: &reqwest::Client,
    url: &str,
    workflow_id: &str,
    token: &str,
    batch: &mut Vec<TraceEvent>,
    ended: bool,
) {
    if batch.is_empty() && !ended {
        return;
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
            batch.clear();
        }
        Ok(res) => {
            log::warn!("ingest rejected: HTTP {}", res.status());
            crate::stats::inc(&crate::stats::INGEST_REJECTED);
            crate::stats::set_last_error(format!("server rejected ingest: HTTP {}", res.status()));
        }
        Err(e) => {
            log::warn!("ingest post failed: {e}");
            crate::stats::inc(&crate::stats::INGEST_FAILED);
            crate::stats::set_last_error(format!("ingest send failed: {e}"));
        }
    }
}

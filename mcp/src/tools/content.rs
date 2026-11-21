//! `discover_content`: ambulo's content discovery on one origin, run as a scan with a
//! handle. Each word takes the place of the marker in the URL's path or query, so every
//! request goes to the one origin the guard cleared, and ambulo dials it only at the
//! address the guard cleared, following no redirect.

use super::engine_scan::{Counting, EngineRun, Plan, Run, start_scan};
use super::{in_range, parse_args};
use crate::core::{CallNote, Done, Intent, Mcp, Refusal, TrafficRequest};
use crate::guard;
use crate::peer::ClientPeer;
use cfx_scope::Point;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// Where each word goes in the URL.
const MARKER: &str = "::FUZZ::";

/// The most words one call tries, and the longest one.
const WORDS_MAX: usize = 5000;
const WORD_MAX: usize = 200;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    url: String,
    words: Vec<String>,
    #[serde(default)]
    wait_seconds: Option<u64>,
}

/// The words, checked: printable, without spaces, and none that could take a request
/// off the URL's origin or out of its path.
fn words(given: Vec<String>) -> Result<Vec<String>, Refusal> {
    let fits = |w: &String| {
        !w.is_empty()
            && w.len() <= WORD_MAX
            && !w.contains("://")
            && !w.starts_with("//")
            && w.chars().all(|c| c.is_ascii_graphic() && c != '\\')
    };
    if given.is_empty() || given.len() > WORDS_MAX || !given.iter().all(fits) {
        return Err(Refusal::invalid(format!(
            "words holds between 1 and {WORDS_MAX} words of at most {WORD_MAX} printable \
             characters each, with no spaces, backslashes or URLs"
        )));
    }
    let mut out: Vec<String> = Vec::with_capacity(given.len());
    for w in given {
        if !out.contains(&w) {
            out.push(w);
        }
    }
    Ok(out)
}

pub(crate) async fn run(
    mcp: &Mcp,
    args: &Value,
    peer: &dyn ClientPeer,
    ct: &CancellationToken,
    note: &mut CallNote,
) -> Result<Done, Refusal> {
    let a: Args = parse_args(args)?;
    let wait = in_range("wait_seconds", a.wait_seconds.unwrap_or(0), 0, 50)?;
    let words = words(a.words)?;
    let dest = guard::parse_target(&a.url).map_err(|e| Refusal::invalid(format!("url: {e}")))?;
    // The marker goes at the end of the path when the URL has none. A URL with a user
    // name, or a host the marker is part of, does not parse as a destination, so the
    // marker is in the path or the query and no word can change where a request goes.
    // One in a fragment would never be sent.
    let endpoint = if dest.url.contains(MARKER) {
        dest.url.clone()
    } else {
        let base = dest.url.split(['?', '#']).next().unwrap_or(&dest.url);
        format!("{}/{MARKER}", base.trim_end_matches('/'))
    };
    if endpoint.matches(MARKER).count() != 1 || endpoint.contains('#') {
        return Err(Refusal::invalid(format!(
            "url has the marker {MARKER} once, in its path or query, or not at all, and no \
             fragment"
        )));
    }

    let pending = mcp
        .precheck(TrafficRequest {
            tool: "discover_content",
            dests: vec![dest.clone()],
            intent: Intent::Read,
            point: Point::Request,
            pace: false,
            scan_start: true,
        })
        .await?;
    let mut fields = Map::new();
    fields.insert("endpoint".into(), json!(endpoint));
    fields.insert("fuzz_marker".into(), json!(MARKER));
    fields.insert("method".into(), json!("get"));
    let plan = Plan {
        tool: "discover_content",
        target: endpoint.clone(),
        run: Run::Engine(EngineRun {
            engine: "ambulo",
            operation: "scan",
            options: &["resolve", "block_internal", "follow_redirects"],
            fields,
            words,
            ack_wait: Duration::from_secs(15),
            phase: "trying paths",
            unit: "paths",
            counting: Counting::Tested,
        }),
        shown_endpoints: vec![endpoint],
        test_writes: false,
        source: None,
        wait,
        write: None,
        on_start: None,
    };
    start_scan(mcp, pending, plan, peer, ct, note).await
}

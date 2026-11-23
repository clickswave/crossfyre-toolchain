//! `find_subdomains`: voyage's enumeration of one domain, run as a scan with a handle.
//!
//! Its passive sources are third-party services asked about the domain, and its names
//! are looked up through the resolvers; neither goes to the target. With words, each is
//! tried as a name under the domain, and a name the resolvers do not answer for is
//! probed over HTTP and HTTPS, which does go to the target. So the scope file has to list
//! the domain for the passive sources alone, and cover the names under it with a `*.`
//! entry for words; voyage is given the file's entries and probes only the names and
//! ports they admit, with redirects off and no internal address dialled.

use super::engine_scan::{Counting, EngineRun, Plan, Run, start_scan};
use super::{in_range, parse_args};
use crate::core::{CallNote, Done, Intent, Mcp, Reason, Refusal, RefusedDest, TrafficRequest};
use crate::peer::ClientPeer;
use crate::untrusted;
use cfx_scope::Point;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// The most words one call tries, and the longest label one can be.
const WORDS_MAX: usize = 5000;
const WORD_MAX: usize = 63;

/// How long voyage may take to acknowledge: it asks its passive sources first.
const PASSIVE_WAIT: Duration = Duration::from_secs(120);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    domain: String,
    #[serde(default)]
    words: Option<Vec<String>>,
    #[serde(default)]
    wait_seconds: Option<u64>,
}

/// The domain, lowercased and checked: a name of labels, not an address or a URL.
fn domain(given: &str) -> Result<String, Refusal> {
    let d = given.trim().trim_end_matches('.').to_ascii_lowercase();
    let label = |l: &str| {
        !l.is_empty() && l.len() <= 63 && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    };
    if d.len() > 253
        || !d.contains('.')
        || !d.split('.').all(label)
        || d.parse::<std::net::IpAddr>().is_ok()
    {
        return Err(Refusal::invalid(
            "domain is a domain name such as example.com, with no scheme, port or path",
        ));
    }
    Ok(d)
}

/// The words, checked: each a label, or labels joined by dots, without repeats.
fn words(given: Vec<String>) -> Result<Vec<String>, Refusal> {
    let fits = |w: &String| {
        !w.is_empty()
            && w.len() <= WORD_MAX
            && w.split('.').all(|l| {
                !l.is_empty()
                    && l.chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            })
    };
    if given.len() > WORDS_MAX || !given.iter().all(fits) {
        return Err(Refusal::invalid(format!(
            "words holds at most {WORDS_MAX} names to try under the domain, each of letters, \
             digits, '-', '_' and dots, at most {WORD_MAX} characters"
        )));
    }
    let mut out: Vec<String> = Vec::with_capacity(given.len());
    for w in given {
        let w = w.to_ascii_lowercase();
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
    let domain = domain(&a.domain)?;
    let words = words(a.words.unwrap_or_default())?;
    let active = !words.is_empty();

    if !mcp.scope.has_entries() {
        return Err(mcp.no_scope());
    }
    if !mcp.scope.scope.admits_zone(&domain, active) {
        let shown = untrusted::clean(&domain, 253);
        return Err(Refusal::new(
            Reason::OutOfScope,
            format!(
                "Out of scope: {shown}. Nothing was sent. {} The scope file {} does not, and \
                 only the person authorised to test it can add it.",
                if active {
                    format!(
                        "Trying words under it looks up and probes names below it, which \
                         needs an entry *.{shown} (or one for a parent domain)."
                    )
                } else {
                    format!(
                        "Asking the passive sources about it needs {shown} or *.{shown} listed."
                    )
                },
                mcp.scope.path.display()
            ),
        )
        .with_refused(vec![RefusedDest {
            host: shown,
            port: 0,
            at: "tool_boundary",
        }]));
    }

    // No destination of its own: the names it finds are fenced by voyage itself, with
    // the scope file's entries, and the caps and the audit are checked as for any scan.
    let pending = mcp
        .precheck(TrafficRequest {
            tool: "find_subdomains",
            dests: Vec::new(),
            intent: Intent::Read,
            point: Point::Request,
            pace: false,
            scan_start: true,
        })
        .await?;
    let mut fields = Map::new();
    fields.insert("domain".into(), json!(domain));
    fields.insert("disable_active".into(), json!(!active));
    let plan = Plan {
        tool: "find_subdomains",
        target: domain.clone(),
        run: Run::Engine(EngineRun {
            engine: "voyage",
            operation: "enum",
            options: &["scope", "follow_redirects", "block_internal"],
            fields,
            words,
            ack_wait: PASSIVE_WAIT,
            phase: "looking up names",
            unit: "names",
            counting: Counting::Results,
        }),
        shown_endpoints: Vec::new(),
        test_writes: false,
        source: None,
        wait,
        write: None,
        on_start: None,
    };
    start_scan(mcp, pending, plan, peer, ct, note).await
}

//! `scan_ports`: doorward's connect scan of one host, run as a scan with a handle. Every
//! port it tries has to be admitted by the scope file for that host, and doorward dials
//! the host only at the address the guard cleared for it.

use super::engine_scan::{Counting, EngineRun, Plan, Run, start_scan};
use super::{in_range, parse_args};
use crate::core::{CallNote, Done, Intent, Mcp, Reason, Refusal, RefusedDest, TrafficRequest};
use crate::guard::{self, Dest};
use crate::peer::ClientPeer;
use crate::untrusted;
use cfx_scope::Point;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// The ports tried when none are given: the services most often left reachable.
const COMMON: [u16; 24] = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900,
    6379, 8080, 8443, 9200, 27017,
];

/// The most ports one call tries.
const PORTS_MAX: usize = 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    host: String,
    #[serde(default)]
    ports: Option<Vec<u16>>,
    #[serde(default)]
    service_detection: Option<bool>,
    #[serde(default)]
    wait_seconds: Option<u64>,
}

/// `host` on `port`, as the guard reads a destination.
fn dest(host: &str, port: u16) -> Result<Dest, Refusal> {
    let at = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    guard::parse_target(&at).map_err(|e| Refusal::invalid(format!("host: {e}")))
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
    let host = a.host.trim();
    if host.is_empty() || host.contains("://") || host.contains('/') {
        return Err(Refusal::invalid(
            "host is one host name or address, with no scheme, port or path",
        ));
    }
    let mut ports = a.ports.unwrap_or_else(|| COMMON.to_vec());
    ports.sort_unstable();
    ports.dedup();
    if ports.is_empty() || ports.len() > PORTS_MAX || ports.contains(&0) {
        return Err(Refusal::invalid(format!(
            "ports holds between 1 and {PORTS_MAX} ports, each from 1 to 65535"
        )));
    }
    let first = dest(host, ports[0])?;

    // Every port tried has to be one the file admits for this host, and each that is
    // not is named, so the person is not walked through them one call at a time.
    let detail = "crossfyre mcp scan_ports";
    let refused: Vec<u16> = ports
        .iter()
        .copied()
        .filter(|p| {
            !mcp.guard
                .admit(&first.host, *p, Point::Request, Some(detail))
        })
        .collect();
    if !refused.is_empty() {
        let shown = untrusted::clean(&first.host, 200);
        let list: Vec<String> = refused.iter().take(20).map(|p| p.to_string()).collect();
        return Err(Refusal::new(
            Reason::OutOfScope,
            format!(
                "Out of scope: {shown} on port{} {}{}. Nothing was sent. The scope file {} \
                 does not list them; scan only the ports it admits for this host.",
                if refused.len() == 1 { "" } else { "s" },
                list.join(", "),
                if refused.len() > 20 { " and more" } else { "" },
                mcp.scope.path.display()
            ),
        )
        .with_refused(
            refused
                .iter()
                .map(|p| RefusedDest {
                    host: shown.clone(),
                    port: *p,
                    at: "tool_boundary",
                })
                .collect(),
        ));
    }

    let pending = mcp
        .precheck(TrafficRequest {
            tool: "scan_ports",
            dests: vec![first.clone()],
            intent: Intent::Read,
            point: Point::Request,
            pace: false,
            scan_start: true,
        })
        .await?;
    let mut fields = Map::new();
    fields.insert("targets".into(), json!([first.host]));
    fields.insert("ports".into(), json!(ports));
    fields.insert(
        "service_detection".into(),
        json!(a.service_detection.unwrap_or(true)),
    );
    fields.insert("adaptive".into(), json!(true));
    let plan = Plan {
        tool: "scan_ports",
        target: first.host.clone(),
        run: Run::Engine(EngineRun {
            engine: "doorward",
            operation: "scan",
            options: &["resolve", "block_internal"],
            fields,
            words: Vec::new(),
            ack_wait: Duration::from_secs(5),
            phase: "trying ports",
            unit: "ports",
            counting: Counting::Progress,
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

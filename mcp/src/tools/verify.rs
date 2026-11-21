//! `verify_finding`: one plessor finding checked again by its proof, the requests that
//! found it sent once more and judged by the same matchers, with nothing else of the scan
//! run. The proof's origin is held to the scope file like any other destination, and a
//! proof whose requests can change the target is sent only with test_writes and a yes.

use super::http::{described, overriding_write, safe};
use super::{in_range, parse_args};
use crate::confirm::{AskKind, WriteAsk};
use crate::core::{CallNote, Done, Intent, Mcp, Reason, Refusal, TrafficRequest};
use crate::engine::{self, Line};
use crate::peer::ClientPeer;
use crate::{guard, kept, redact, untrusted};
use cfx_cve::inventory::NOT_PROOF;
use cfx_scope::Point;
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    finding_id: String,
    #[serde(default)]
    test_writes: bool,
    #[serde(default)]
    timeout_seconds: Option<u64>,
}

/// One request of a proof, as this server reads it to decide what it may do.
struct Request {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: Option<String>,
}

fn requests(proof: &Value) -> Vec<Request> {
    proof["requests"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|r| Request {
            method: r["method"]
                .as_str()
                .unwrap_or_default()
                .to_ascii_uppercase(),
            url: r["url"].as_str().unwrap_or_default().to_string(),
            headers: r["fields"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|f| Some((f[0].as_str()?.to_string(), f[1].as_str()?.to_string())))
                .collect(),
            body: r["body"].as_str().map(str::to_string),
        })
        .collect()
}

/// How a write question names the first of `reqs` that can change the target, or None
/// when none can: a method other than GET, HEAD or OPTIONS, or one that asks for another
/// method by override.
fn first_write(reqs: &[Request]) -> Option<String> {
    reqs.iter().find_map(|r| {
        let overridden = if safe(&r.method) {
            overriding_write(&r.url, &r.headers, r.body.as_deref())
        } else {
            None
        };
        (!safe(&r.method) || overridden.is_some())
            .then(|| described(&r.method, overridden.as_ref()))
    })
}

fn not_verifiable(id: &str, why: &str) -> Refusal {
    Refusal::new(
        Reason::NotVerifiable,
        format!(
            "Finding {id} was not checked again: {}. Nothing was sent.",
            untrusted::clean(why, 300)
        ),
    )
}

pub(crate) async fn run(
    mcp: &Mcp,
    args: &Value,
    peer: &dyn ClientPeer,
    ct: &CancellationToken,
    note: &mut CallNote,
) -> Result<Done, Refusal> {
    let a: Args = parse_args(args)?;
    let timeout = in_range("timeout_seconds", a.timeout_seconds.unwrap_or(10), 1, 60)?;
    let own = match kept::parse_finding_id(&a.finding_id) {
        Some(("plessor", own)) => own,
        Some(_) => {
            return Err(not_verifiable(
                &a.finding_id,
                "only plessor's template findings keep a proof to send again",
            ));
        }
        None => {
            return Err(Refusal::invalid(
                "finding_id is f_plessor_ and plessor's id for the finding",
            ));
        }
    };
    let (_, row, of) = kept::kept_finding(mcp, &a.finding_id)
        .await
        .ok_or_else(|| Refusal::new(Reason::NotFound, "no finding with that id"))?;
    note.set_scan(of.id.clone());
    let Some(proof) = row["data"].get("proof").filter(|p| p.is_object()) else {
        return Err(not_verifiable(
            &a.finding_id,
            "it has no proof kept, as an injection or authorization finding has none",
        ));
    };
    let reqs = requests(proof);
    let Some(first) = reqs.first() else {
        return Err(not_verifiable(&a.finding_id, "its proof holds no request"));
    };
    let dest = guard::parse_target(&first.url)
        .map_err(|e| not_verifiable(&a.finding_id, &format!("its proof's URL: {e}")))?;
    if reqs
        .iter()
        .any(|r| guard::parse_target(&r.url).map(|d| d.origin()).ok() != Some(dest.origin()))
    {
        return Err(not_verifiable(
            &a.finding_id,
            "its proof's requests do not all go to one origin",
        ));
    }
    let writes = first_write(&reqs);
    if let Some(w) = &writes
        && !a.test_writes
    {
        return Err(Refusal::invalid(format!(
            "finding {}'s proof sends a {w}, which can change or destroy data; it is sent again \
             only with test_writes, which needs allow_writes in the scope file and a \
             confirmation",
            a.finding_id
        )));
    }

    let pending = mcp
        .precheck(TrafficRequest {
            tool: "verify_finding",
            dests: vec![dest.clone()],
            intent: if writes.is_some() {
                Intent::Write
            } else {
                Intent::Read
            },
            point: Point::Request,
            pace: true,
            scan_start: false,
        })
        .await?;
    let port = mcp.engine("plessor")?.port;
    let mut conn = engine::connect(port)
        .await
        .map_err(|_| mcp.engine_down("plessor", port))?;
    mcp.require(
        &mut conn,
        "plessor",
        port,
        "verify",
        &["follow_redirects", "resolve"],
    )
    .await?;
    let write = writes.as_ref().map(|w| WriteAsk {
        remember: None,
        message: format!(
            "verify_finding will send the {} requests of finding {}'s proof to {} again, among \
             them a {w}. That can change or destroy data.",
            reqs.len(),
            a.finding_id,
            untrusted::clean(&dest.origin(), 200)
        ),
        kind: AskKind::Write,
    });
    let clearance = mcp.confirm(pending, peer, write, note, ct).await?;
    if ct.is_cancelled() {
        return Err(Refusal::new(
            Reason::Cancelled,
            "The call was cancelled before anything was sent.",
        ));
    }

    // As for a scan: no redirect followed, and the origin dialled only at the address the
    // guard cleared for it, with the internal-address filter on for anything else.
    let op = json!({
        "operation": "verify",
        "response": "instant",
        "finding": own,
        "test_writes": a.test_writes,
        "follow_redirects": false,
        "resolve": clearance.pins(),
        "block_internal": clearance.block_internal(mcp.scope.allow_private),
        "timeout_ms": timeout * 1000,
    });
    let (mut reader, _writer) = conn.start(&clearance, &op).await.map_err(|e| {
        Refusal::new(
            Reason::EngineError,
            format!("could not send to plessor: {e}"),
        )
    })?;
    // Each request waits its timeout at most, and a check confirmed by a callback waits
    // for the callback too.
    let deadline = Duration::from_secs(timeout * reqs.len() as u64 + 15);
    let answer = tokio::select! {
        _ = ct.cancelled() => {
            return Err(Refusal::new(
                Reason::Cancelled,
                "The call was cancelled while plessor was sending the proof's requests.",
            ));
        }
        r = tokio::time::timeout(deadline, reader.next()) => r,
    };
    let answer = match answer {
        Ok(Ok(Some(Line::Event(v)))) => v,
        Err(_) => {
            return Err(Refusal::new(
                Reason::EngineError,
                "plessor did not answer in time",
            ));
        }
        _ => {
            return Err(Refusal::new(
                Reason::EngineError,
                "plessor closed the connection without an answer",
            ));
        }
    };
    if answer["status"] != "completed" {
        let message = answer["message"]
            .as_str()
            .unwrap_or("plessor gave no reason");
        return Err(match message.strip_prefix("not replayed: ") {
            Some(why) => not_verifiable(&a.finding_id, why),
            None => Refusal::new(
                Reason::EngineError,
                format!(
                    "plessor reported: {}",
                    untrusted::clean(message, untrusted::NOTE_CAP)
                ),
            ),
        });
    }

    let said = answer["answer"].as_str().unwrap_or_default().to_string();
    let redact = mcp.settings.redact;
    let shown = |s: &str| kept::masked(&of, &untrusted::clean(s, 2000), redact);
    let fired: Vec<Value> = answer["fired"]
        .as_array()
        .into_iter()
        .flatten()
        .take(20)
        .map(|f| {
            json!({
                "matcher": untrusted::clean(f["matcher"].as_str().unwrap_or_default(), 40),
                "part": untrusted::clean(f["part"].as_str().unwrap_or_default(), 40),
                "evidence": shown(f["evidence"].as_str().unwrap_or_default()),
            })
        })
        .collect();
    let origin = untrusted::clean(&dest.origin(), 200);
    let mut value = json!({
        "finding_id": a.finding_id,
        "scan_id": of.id,
        "origin": if redact { redact::redact_url(&origin) } else { origin.clone() },
        "answer": said,
        "http_status": answer["http_status"].as_u64(),
        "response_sha256": answer["response_sha256"].as_str().unwrap_or_default(),
        "target_data": {"untrusted": true, "fired": fired},
    });
    if said == "not reproduced" {
        value["note"] = json!(NOT_PROOF);
    }
    note.result = Some(json!({"answer": said, "http_status": value["http_status"]}));
    let summary = format!(
        "plessor sent finding {}'s proof to {} again: {}{}.{}",
        a.finding_id,
        origin,
        said,
        value["http_status"]
            .as_u64()
            .map(|s| format!(" (HTTP {s})"))
            .unwrap_or_default(),
        if said == "not reproduced" {
            format!(" {NOT_PROOF}")
        } else {
            String::new()
        }
    );
    Ok(Done { value, summary })
}

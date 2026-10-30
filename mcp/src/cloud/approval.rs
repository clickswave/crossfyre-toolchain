//! A launch the workspace holds for a person to approve.
//!
//! The platform stores the request and launches it as stored once someone decides, so
//! nothing the agent sends afterwards can change what was approved. The call waits for
//! that decision, up to the earlier of the approval's expiry and a fixed limit:
//!
//! - when the key's owner has a phone registered, only the phone can approve, so the
//!   call waits and says which phone it is waiting on;
//! - with no phone, and a workspace that allows the fallback, the person is asked in
//!   the agent's own client: sent to the approval page when the client can open a
//!   URL, or else shown what would launch in a form whose answer is sent as the
//!   decision;
//! - otherwise the answer is the `ap_` handle and the page where it can be decided.
//!
//! A form answered in the agent's client stops a model's mistake, not a stolen key; the
//! platform records which way each approval was decided.

use super::route::approval_result;
use super::{Cloud, CloudNote, shape};
use crate::core::{CallNote, Done, Mcp, Reason, Refusal};
use crate::peer::{Answer, ClientPeer};
use crate::untrusted;
use cfx_cloud_wire::{self as wire, ApprovalStatus, IdKind, LaunchState};
use serde_json::json;
use std::time::Duration;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// Still to be decided, or decided and still being launched.
fn open(a: &wire::Approval) -> bool {
    match a.status {
        ApprovalStatus::Pending => true,
        ApprovalStatus::Approved => matches!(a.launch_state, None | Some(LaunchState::Launching)),
        _ => false,
    }
}

/// When the approval stops being worth waiting for: its expiry, or the call's limit.
fn deadline(cloud: &Cloud, a: &wire::Approval) -> Instant {
    let limit = Instant::now() + cloud.approval_wait;
    let expires = chrono::DateTime::parse_from_rfc3339(a.expires_at.trim())
        .ok()
        .map(|t| t.timestamp_millis() - chrono::Utc::now().timestamp_millis())
        .map(|ms| Instant::now() + Duration::from_millis(ms.max(0) as u64));
    expires.map_or(limit, |e| e.min(limit))
}

fn confirmation(a: &wire::Approval) -> Option<&'static str> {
    match a.decided_via? {
        wire::DecidedVia::Phone => Some("approval:phone"),
        wire::DecidedVia::Dashboard => Some("approval:dashboard"),
        wire::DecidedVia::AgentClient => Some("approval:agent_client"),
        wire::DecidedVia::Other => Some("approval:other"),
    }
}

/// What the form shows: what the platform stored, so the person approves what would
/// actually launch.
fn summary(cloud: &Cloud, a: &wire::Approval) -> Option<String> {
    let act = a.action.as_ref()?;
    let targets: Vec<String> = act
        .targets
        .iter()
        .take(20)
        .map(|t| shape::target(t).unwrap_or_else(|| "(a target that does not parse)".into()))
        .collect();
    let workspace = cloud
        .whoami()
        .map(|w| untrusted::clean(&w.workspace.name, 200))
        .unwrap_or_else(|| "the key's workspace".into());
    Some(format!(
        "An agent asks to start a {} scan on {} node(s) of {workspace}, against: {}. It runs \
         exactly as shown once approved. Approve it?",
        act.kind.as_str(),
        act.nodes,
        targets.join(", ")
    ))
}

#[allow(clippy::too_many_arguments)]
async fn decide(
    mcp: &Mcp,
    cloud: &Cloud,
    peer: &dyn ClientPeer,
    tool: &str,
    uuid: &str,
    yes: bool,
    note: &mut CallNote,
) -> Result<wire::Approval, Refusal> {
    let req = wire::DecideRequest {
        id: uuid.to_string(),
        decision: if yes {
            wire::Decision::Approve
        } else {
            wire::Decision::Deny
        },
        via: wire::Via::AgentClient,
    };
    let got: Result<(u16, wire::ApprovalAnswer), Refusal> = cloud
        .request(
            mcp,
            peer,
            tool,
            wire::route::APPROVALS_DECIDE,
            serde_json::to_value(&req).unwrap_or_default(),
            Duration::ZERO,
            note,
        )
        .await;
    match got {
        Ok((_, a)) => Ok(a.approval),
        // Decided elsewhere in the meantime: read what was decided.
        Err(r) if r.reason == Reason::CloudRefused(wire::Reason::AlreadyDecided.as_str()) => {
            let (_, a): (u16, wire::ApprovalAnswer) = cloud
                .request(
                    mcp,
                    peer,
                    tool,
                    wire::route::APPROVALS_GET,
                    json!({"id": uuid}),
                    Duration::ZERO,
                    note,
                )
                .await?;
            Ok(a.approval)
        }
        Err(r) => Err(r),
    }
}

/// After `scans/start` answered 202.
pub(super) async fn wait(
    mcp: &Mcp,
    cloud: &Cloud,
    tool: &str,
    first: &wire::Approval,
    peer: &dyn ClientPeer,
    ct: &CancellationToken,
    note: &mut CallNote,
) -> Result<Done, Refusal> {
    let Some(ap) = wire::encode(IdKind::Approval, &first.id) else {
        return Err(Refusal::new(
            Reason::CloudUnavailable,
            "The Cloud answered with an approval id this crossfyre does not read.",
        ));
    };
    note.cloud
        .get_or_insert_with(CloudNote::default)
        .approval_id = Some(ap.clone());
    note.set_scan(ap.clone());
    let uuid = first.id.clone();
    let until = deadline(cloud, first);
    let page = shape::approve_url(first, &cloud.config.api_url);
    let mut a = first.clone();

    // Who can decide, and whether this client can ask them.
    let phones: Vec<String> = a
        .devices
        .iter()
        .take(3)
        .map(|d| untrusted::clean(&d.name, 64))
        .collect();
    let waiting_on = if !phones.is_empty() {
        format!("Waiting for approval on {}", phones.join(", "))
    } else if a.fallback && peer.can_elicit_url() && page.is_some() {
        let url = page.clone().unwrap_or_default();
        let asked = tokio::select! {
            r = peer.open_url(
                "Approve this scan in the browser: the page shows what would start, and on \
                 which nodes."
                    .into(),
                url,
                ap.clone(),
            ) => r,
            _ = ct.cancelled() => return Err(still_pending(&ap)),
        };
        if asked != Answer::Yes {
            return approval_result(mcp, cloud, peer, tool, &a, note).await;
        }
        "Waiting for the decision in the browser".to_string()
    } else if a.fallback && peer.can_elicit_form() {
        let Some(message) = summary(cloud, &a) else {
            return approval_result(mcp, cloud, peer, tool, &a, note).await;
        };
        let asked = tokio::select! {
            r = peer.confirm(message, "approve", "Approve this launch") => r,
            _ = ct.cancelled() => return Err(still_pending(&ap)),
        };
        match asked {
            Answer::Yes => a = decide(mcp, cloud, peer, tool, &uuid, true, note).await?,
            Answer::No => a = decide(mcp, cloud, peer, tool, &uuid, false, note).await?,
            // Left for the person to decide on the approval page.
            Answer::Dismissed => return approval_result(mcp, cloud, peer, tool, &a, note).await,
        }
        "Waiting for the approved scan to start".to_string()
    } else {
        return approval_result(mcp, cloud, peer, tool, &a, note).await;
    };

    // Wait for the decision, and after an approval for the launch, a long poll at a time.
    let mut polls = 0u32;
    while open(&a) {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        polls += 1;
        peer.progress(f64::from(polls), None, &waiting_on).await;
        let hold = left.as_secs().clamp(1, u64::from(wire::MAX_WAIT_SECONDS)) as u32;
        let started = Instant::now();
        let asked = cloud.request::<wire::ApprovalAnswer>(
            mcp,
            peer,
            tool,
            wire::route::APPROVALS_WAIT,
            serde_json::to_value(wire::WaitRequest {
                id: uuid.clone(),
                wait_seconds: hold,
            })
            .unwrap_or_default(),
            Duration::from_secs(u64::from(hold)),
            note,
        );
        let got = tokio::select! {
            r = asked => r?,
            _ = ct.cancelled() => return Err(still_pending(&ap)),
        };
        a = got.1.approval;
        // A platform that answers at once is not asked again straight away.
        if open(&a) && started.elapsed() < cloud.poll_every {
            let pause = cloud
                .poll_every
                .min(until.saturating_duration_since(Instant::now()));
            tokio::select! {
                _ = tokio::time::sleep(pause) => {}
                _ = ct.cancelled() => return Err(still_pending(&ap)),
            }
        }
    }
    if let Some(c) = confirmation(&a) {
        note.confirmation = Some(c);
    }
    approval_result(mcp, cloud, peer, tool, &a, note).await
}

fn still_pending(ap: &str) -> Refusal {
    Refusal::new(
        Reason::Cancelled,
        format!(
            "The call was cancelled while it waited. Launch {ap} still waits for a person; \
             get_scan shows what became of it, and cancel_scan withdraws it."
        ),
    )
}

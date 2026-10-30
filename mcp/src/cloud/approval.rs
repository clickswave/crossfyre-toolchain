//! A launch the workspace holds for a person to approve. The platform stores the
//! request and launches it as stored once someone decides, so nothing the agent sends
//! afterwards can change what was approved.

use super::route::approval_result;
use super::{Cloud, CloudNote};
use crate::core::{CallNote, Done, Mcp, Refusal};
use crate::peer::ClientPeer;
use cfx_cloud_wire::{self as wire, IdKind};
use tokio_util::sync::CancellationToken;

/// After `scans/start` answered 202: say where the launch can be decided.
pub(super) async fn wait(
    mcp: &Mcp,
    cloud: &Cloud,
    tool: &str,
    a: &wire::Approval,
    peer: &dyn ClientPeer,
    _ct: &CancellationToken,
    note: &mut CallNote,
) -> Result<Done, Refusal> {
    let id = wire::encode(IdKind::Approval, &a.id);
    note.cloud
        .get_or_insert_with(CloudNote::default)
        .approval_id = id.clone();
    if let Some(id) = id {
        note.set_scan(id);
    }
    approval_result(mcp, cloud, peer, tool, a, note).await
}

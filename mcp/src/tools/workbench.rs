//! The `workbench_*` tools: a running Crossfyre Workbench's project, read and sent
//! through over its local socket.

use crate::WorkbenchMode;
use crate::core::{CallNote, Done, Mcp, Reason, Refusal};
use crate::peer::ClientPeer;
use serde_json::Value;
use tokio_util::sync::CancellationToken;

pub(crate) async fn run(
    mcp: &Mcp,
    _tool: &str,
    _args: &Value,
    _peer: &dyn ClientPeer,
    _ct: &CancellationToken,
    _note: &mut CallNote,
) -> Result<Done, Refusal> {
    Err(unavailable(mcp))
}

/// No Workbench to answer: what to do about it, in the person's terms.
pub(crate) fn unavailable(mcp: &Mcp) -> Refusal {
    let message = if mcp.settings.workbench == WorkbenchMode::Off {
        "This server was started with --workbench off, so it reaches no Workbench. Nothing \
         was read or sent."
    } else if !cfg!(unix) {
        "The Workbench bridge is not available on this platform. Nothing was read or sent."
    } else {
        "No Crossfyre Workbench with Agent access on is answering, so nothing was read or \
         sent. Open the Workbench (0.1.2 or later), turn Agent access on with the Agents chip \
         in its status bar, and call again. status shows what this server found."
    };
    Refusal::new(Reason::WorkbenchUnavailable, message)
}

/// The `workbench` object in `status`.
pub(crate) fn status(mcp: &Mcp) -> Value {
    serde_json::json!({
        "mode": mcp.settings.workbench.as_str(),
        "supported": cfg!(unix),
        "instances": [],
        "ignored": [],
    })
}

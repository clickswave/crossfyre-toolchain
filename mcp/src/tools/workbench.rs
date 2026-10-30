//! The `workbench_*` tools: a running Crossfyre Workbench's project, read and sent
//! through over its local socket.

use crate::WorkbenchMode;
use crate::core::{CallNote, Done, Mcp, Reason, Refusal};
use crate::peer::ClientPeer;
use serde_json::{Value, json};
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

/// The `workbench` object in `status`, and its hints.
pub(crate) async fn status(mcp: &Mcp, hints: &mut Vec<String>) -> Value {
    let mut v = json!({
        "mode": mcp.settings.workbench.as_str(),
        "supported": cfg!(unix),
        "dir": null,
        "instances": [],
        "ignored": [],
    });
    if mcp.settings.workbench == WorkbenchMode::Off {
        return v;
    }
    if !cfg!(unix) {
        hints.push("the Workbench bridge is not available on this platform".into());
        return v;
    }
    let found = mcp.workbench.status(hints).await;
    if let (Some(o), Some(f)) = (v.as_object_mut(), found.as_object()) {
        for (k, x) in f {
            o.insert(k.clone(), x.clone());
        }
    }
    let none = v["instances"].as_array().is_none_or(|a| a.is_empty());
    if none && mcp.settings.workbench == WorkbenchMode::Always {
        hints.push(
            "no Crossfyre Workbench with Agent access on was found, so the workbench_* tools \
             refuse; open one (0.1.2 or later) and turn Agent access on"
                .into(),
        );
    }
    v
}

//! The Cloud-only read tools: `whoami`, `list_nodes`, `list_assets`, `get_asset`.

use super::{Cloud, shape};
use crate::core::{CallNote, Done, Mcp, Reason, Refusal};
use crate::peer::ClientPeer;
use crate::tools::{NoArgs, in_range, parse_args};
use crate::untrusted;
use cfx_cloud_wire::{self as wire, IdKind};
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Duration;

pub(super) async fn run(
    mcp: &Mcp,
    cloud: &Cloud,
    tool: &str,
    args: &Value,
    peer: &dyn ClientPeer,
    note: &mut CallNote,
) -> Result<Done, Refusal> {
    match tool {
        "whoami" => whoami(mcp, cloud, args, peer, note).await,
        "list_nodes" => list_nodes(mcp, cloud, args, peer, note).await,
        "list_assets" => list_assets(mcp, cloud, args, peer, note).await,
        "get_asset" => get_asset(mcp, cloud, args, peer, note).await,
        _ => Err(Refusal::new(Reason::UnknownTool, "unknown tool")),
    }
}

/// A Cloud id the model gave, checked for its kind.
pub(super) fn decode(id: &str, kind: IdKind, field: &str) -> Result<String, Refusal> {
    match wire::decode(id) {
        Some((k, uuid)) if k == kind => Ok(uuid),
        _ => Err(Refusal::invalid(format!(
            "{field} is {} followed by 32 lowercase hex characters",
            kind.prefix()
        ))),
    }
}

/// An opaque cursor the platform gave, checked before it goes back.
pub(super) fn cursor(c: Option<&str>) -> Result<Option<String>, Refusal> {
    match c {
        None => Ok(None),
        Some(c)
            if !c.is_empty()
                && c.len() <= 512
                && c.bytes().all(|b| b.is_ascii_graphic() && b != b'|') =>
        {
            Ok(Some(c.to_string()))
        }
        Some(_) => Err(Refusal::invalid("cursor is not one this server returned")),
    }
}

async fn whoami(
    mcp: &Mcp,
    cloud: &Cloud,
    args: &Value,
    peer: &dyn ClientPeer,
    note: &mut CallNote,
) -> Result<Done, Refusal> {
    let _: NoArgs = parse_args(args)?;
    let (_, w): (u16, wire::Whoami) = cloud
        .request(
            mcp,
            peer,
            "whoami",
            wire::route::WHOAMI,
            json!({}),
            Duration::ZERO,
            note,
        )
        .await?;
    cloud.set_whoami(w.clone());
    cloud.announce(mcp, peer).await;
    let value = json!({
        "backend": "cloud",
        "key": {
            "prefix": cloud.key_prefix(),
            "permission": w.key.permission.as_str(),
            "expires_at": shape::timestamp(&w.key.expires_at),
        },
        "workspace": {"id": wire::is_uuid(&w.workspace.id).then_some(&w.workspace.id)},
        "plan": untrusted::clean(&w.plan, 64),
        "limits": {
            "running_workflows": w.limits.running_workflows,
            "max_concurrent_workflows": w.limits.max_concurrent_workflows,
            "monthly_used": w.limits.monthly_used,
            "monthly_cap": w.limits.monthly_cap,
            "launches_left_this_hour": w.limits.launches_left_this_hour,
            "key_concurrent_cap": w.limits.key_concurrent_cap,
        },
        "approval": {
            "policy": w.approval.policy.as_str(),
            "fallback": w.approval.fallback,
            "phone_registered": w.approval.phone_registered,
        },
        "scope": {
            "workspace_entries": w.scope.current,
            "attested_entries": w.scope.attested,
            "effective_entries": w.scope.effective,
            "effective_sha256": untrusted::clean(&w.scope.effective_sha256, 64),
        },
        "workspace_text": shape::workspace_text(&[
            ("workspace", Some(&w.workspace.name)),
            ("key_name", Some(&w.key.name)),
            ("username", Some(&w.user.username)),
        ]),
    });
    let summary = format!(
        "Cloud key {} ({}), {} scope entries a launch may target.",
        cloud.key_prefix(),
        w.key.permission.as_str(),
        w.scope.effective
    );
    Ok(Done { value, summary })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NodesArgs {
    #[serde(default)]
    online_only: Option<bool>,
}

async fn list_nodes(
    mcp: &Mcp,
    cloud: &Cloud,
    args: &Value,
    peer: &dyn ClientPeer,
    note: &mut CallNote,
) -> Result<Done, Refusal> {
    let a: NodesArgs = parse_args(args)?;
    let (_, n): (u16, wire::Nodes) = cloud
        .request(
            mcp,
            peer,
            "list_nodes",
            wire::route::NODES_LIST,
            serde_json::to_value(wire::NodesRequest {
                online_only: a.online_only,
            })
            .unwrap_or_default(),
            Duration::ZERO,
            note,
        )
        .await?;
    let nodes: Vec<Value> = n.nodes.iter().take(200).map(shape::node).collect();
    let online = nodes.iter().filter(|n| n["status"] == "online").count();
    let summary = format!("{} node(s), {online} online.", nodes.len());
    Ok(Done {
        value: json!({"nodes": nodes}),
        summary,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssetsArgs {
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    search: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    limit: Option<u64>,
}

async fn list_assets(
    mcp: &Mcp,
    cloud: &Cloud,
    args: &Value,
    peer: &dyn ClientPeer,
    note: &mut CallNote,
) -> Result<Done, Refusal> {
    let a: AssetsArgs = parse_args(args)?;
    let limit = in_range("limit", a.limit.unwrap_or(20), 1, 50)? as u32;
    if let Some(k) = &a.kind
        && !wire::vocab::is_word(k)
    {
        return Err(Refusal::invalid(
            "type is a lowercase word such as domain or url",
        ));
    }
    if let Some(s) = &a.status
        && !wire::vocab::ASSET_STATUSES.contains(&s.as_str())
    {
        return Err(Refusal::invalid(format!(
            "status must be one of {}",
            wire::vocab::ASSET_STATUSES.join(", ")
        )));
    }
    let given = cursor(a.cursor.as_deref())?;
    let search = a.search.map(|s| untrusted::clean(&s, 200));
    let mut lim = limit;
    loop {
        let req = wire::AssetsRequest {
            kind: a.kind.clone(),
            search: search.clone(),
            status: a.status.clone(),
            cursor: given.clone(),
            limit: Some(lim),
        };
        let (_, page): (u16, wire::Assets) = cloud
            .request(
                mcp,
                peer,
                "list_assets",
                wire::route::ASSETS_LIST,
                serde_json::to_value(req).unwrap_or_default(),
                Duration::ZERO,
                note,
            )
            .await?;
        let rows: Vec<Value> = page
            .assets
            .iter()
            .take(lim as usize)
            .map(|r| shape::asset_row(r, mcp.settings.redact))
            .collect();
        let next = cursor(page.next_cursor.as_deref()).ok().flatten();
        let build = |k: usize| {
            let summary = format!(
                "{k} asset(s), most recently seen first{}.",
                if next.is_some() {
                    "; pass next_cursor to read on"
                } else {
                    ""
                }
            );
            (summary, json!({"assets": rows[..k], "next_cursor": next}))
        };
        let k = super::fit_count(rows.len(), build);
        // A page cut to fit is asked for again at the size that fits, so the cursor
        // continues exactly after the last asset returned.
        if k < rows.len() && lim > 1 {
            lim = k as u32;
            continue;
        }
        let (summary, value) = build(k);
        return Ok(Done { value, summary });
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssetArgs {
    asset_id: String,
}

async fn get_asset(
    mcp: &Mcp,
    cloud: &Cloud,
    args: &Value,
    peer: &dyn ClientPeer,
    note: &mut CallNote,
) -> Result<Done, Refusal> {
    let a: AssetArgs = parse_args(args)?;
    let uuid = decode(&a.asset_id, IdKind::Asset, "asset_id")?;
    let (_, got): (u16, wire::AssetGet) = cloud
        .request(
            mcp,
            peer,
            "get_asset",
            wire::route::ASSETS_GET,
            json!({"id": uuid}),
            Duration::ZERO,
            note,
        )
        .await?;
    let mut value = shape::asset_detail(&got.asset, mcp.settings.redact);
    let summary = format!(
        "Asset {} ({}), {} recent verdict(s).",
        a.asset_id,
        value["type"].as_str().unwrap_or("other"),
        value["recent_verdicts"]
            .as_array()
            .map(|v| v.len())
            .unwrap_or(0)
    );
    super::shrink(&summary, &mut value);
    Ok(Done { value, summary })
}

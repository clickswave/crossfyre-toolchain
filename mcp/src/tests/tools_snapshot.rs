//! The tool definitions are a contract with every client that has read them.
//!
//! A change to a name, a hint or a schema changes what a client lets a model do, so it
//! has to be made on purpose: this hash is updated in the same change as the file.

use crate::scope_file::sha256_hex;
use crate::tools::{
    Backends, NAMES, TARGET_DATA_TOOLS, TOOLS_JSON, TOOLS_WORKBENCH_JSON, UNTRUSTED_DESCRIPTION,
    WORKBENCH_NAMES,
};
use serde_json::Value;

/// sha256 of `tools.json` with CRLF read as LF, so a Windows checkout agrees.
const PINNED: &str = "44b679945567316a287513b2e07be2bed1ff0c1a4ed23e60ca8ab6c73f5f63e1";

/// The same for `tools_workbench.json`.
const PINNED_WORKBENCH: &str = "ee94f06fe0ae72f9c549b53782503e9b7cad21865b2406cf1d484ce2c29ba073";

#[test]
fn the_definitions_are_pinned() {
    let normalised = TOOLS_JSON.replace("\r\n", "\n");
    assert_eq!(
        sha256_hex(normalised.as_bytes()),
        PINNED,
        "tools.json changed; if that was deliberate, update PINNED in the same change"
    );
}

#[test]
fn every_tool_is_described_completely() {
    let tools: Vec<Value> = serde_json::from_str(TOOLS_JSON).unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names, NAMES);
    for t in &tools {
        let name = t["name"].as_str().unwrap();
        assert!(name.len() <= 64);
        assert!(!t["title"].as_str().unwrap_or("").is_empty(), "{name}");
        assert_eq!(t["annotations"]["title"], t["title"], "{name}");
        for hint in [
            "readOnlyHint",
            "destructiveHint",
            "idempotentHint",
            "openWorldHint",
        ] {
            assert!(t["annotations"][hint].is_boolean(), "{name} {hint}");
        }
        assert_eq!(t["inputSchema"]["type"], "object", "{name}");
        assert_eq!(t["inputSchema"]["additionalProperties"], false, "{name}");
        assert_eq!(t["outputSchema"]["type"], "object", "{name}");
        let d = t["description"].as_str().unwrap();
        let mentions = d.matches(UNTRUSTED_DESCRIPTION).count();
        let expected = usize::from(TARGET_DATA_TOOLS.contains(&name));
        assert_eq!(mentions, expected, "{name}");
    }
    let hints = |n: &str| {
        let t = tools.iter().find(|t| t["name"] == n).unwrap();
        let a = &t["annotations"];
        (
            a["readOnlyHint"].as_bool().unwrap(),
            a["destructiveHint"].as_bool().unwrap(),
            a["idempotentHint"].as_bool().unwrap(),
            a["openWorldHint"].as_bool().unwrap(),
        )
    };
    for n in ["status", "get_scope", "check_scope", "list_scans"] {
        assert_eq!(hints(n), (true, false, true, false), "{n}");
    }
    for n in ["get_scan", "list_findings", "get_finding"] {
        assert_eq!(hints(n), (true, false, true, true), "{n}");
    }
    assert_eq!(hints("fingerprint"), (false, false, false, true));
    assert_eq!(hints("test_injection"), (false, true, false, true));
    assert_eq!(hints("scan_templates"), (false, true, false, true));
    assert_eq!(hints("verify_finding"), (false, true, false, true));
    assert_eq!(hints("get_inventory"), (true, false, true, true));
    assert_eq!(hints("send_http_request"), (false, true, false, true));
    assert_eq!(hints("cancel_scan"), (false, false, true, false));
}

/// A tool that can say a check found nothing says, in the words the leads use, that this
/// is not proof the host is safe.
#[test]
fn every_tool_that_answers_a_check_says_a_negative_is_not_proof() {
    let tools: Vec<Value> = serde_json::from_str(TOOLS_JSON).unwrap();
    for name in ["scan_templates", "verify_finding", "get_inventory"] {
        let t = tools.iter().find(|t| t["name"] == name).unwrap();
        let d = t["description"].as_str().unwrap();
        assert!(d.contains(cfx_cve::inventory::NOT_PROOF), "{name}: {d}");
        assert!(!d.contains("not exploitable"), "{name}");
    }
}

#[test]
fn the_workbench_definitions_are_pinned() {
    let normalised = TOOLS_WORKBENCH_JSON.replace("\r\n", "\n");
    assert_eq!(
        sha256_hex(normalised.as_bytes()),
        PINNED_WORKBENCH,
        "tools_workbench.json changed; if that was deliberate, update PINNED_WORKBENCH"
    );
}

#[test]
fn every_workbench_tool_is_described_completely() {
    let tools: Vec<Value> = serde_json::from_str(TOOLS_WORKBENCH_JSON).unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names, WORKBENCH_NAMES);
    for t in &tools {
        let name = t["name"].as_str().unwrap();
        assert!(name.len() <= 64);
        assert!(!t["title"].as_str().unwrap_or("").is_empty(), "{name}");
        assert_eq!(t["annotations"]["title"], t["title"], "{name}");
        assert_eq!(t["inputSchema"]["type"], "object", "{name}");
        assert_eq!(t["inputSchema"]["additionalProperties"], false, "{name}");
        assert_eq!(t["outputSchema"]["type"], "object", "{name}");
        // Every one of them returns something a target wrote.
        let d = t["description"].as_str().unwrap();
        assert_eq!(d.matches(UNTRUSTED_DESCRIPTION).count(), 1, "{name}");
        let a = &t["annotations"];
        let hints = (
            a["readOnlyHint"].as_bool().unwrap(),
            a["destructiveHint"].as_bool().unwrap(),
            a["idempotentHint"].as_bool().unwrap(),
            a["openWorldHint"].as_bool().unwrap(),
        );
        let expected = match name {
            "workbench_replay" | "workbench_test_injection" => (false, true, false, true),
            _ => (true, false, true, true),
        };
        assert_eq!(hints, expected, "{name}");
        // No schema asks a model for a secret.
        let schema = t["inputSchema"].to_string().to_ascii_lowercase();
        for word in ["\"token\"", "\"api_key\"", "\"key\"", "\"authorization\""] {
            assert!(!schema.contains(word), "{name} takes {word}");
        }
    }
}

#[test]
fn the_protocol_layer_reads_them() {
    let all = |b: &Backends| crate::server::tool_list(b);
    let off = all(&Backends {
        workbench: None,
        ..Default::default()
    });
    assert_eq!(off.len(), 14);
    assert!(
        off.iter()
            .all(|t| t.output_schema.is_some() && t.annotations.is_some())
    );
    assert_eq!(
        all(&Backends {
            workbench: Some(Vec::new()),
            ..Default::default()
        })
        .len(),
        14
    );
    let every = all(&Backends {
        workbench: Some(WORKBENCH_NAMES.to_vec()),
        ..Default::default()
    });
    assert_eq!(every.len(), 21);
    assert!(
        every
            .iter()
            .all(|t| t.output_schema.is_some() && t.annotations.is_some())
    );
    let some = all(&Backends {
        workbench: Some(vec!["workbench_get_scope"]),
        ..Default::default()
    });
    assert_eq!(some.last().unwrap().name, "workbench_get_scope");
    assert_eq!(some.len(), 15);
}

#[test]
fn the_server_says_its_tool_list_can_change() {
    use rmcp::ServerHandler;
    let t = super::support::scope(&[], "").build();
    let server = crate::server::Server {
        mcp: std::sync::Arc::clone(&t.mcp),
    };
    let info = server.get_info();
    let tools = info.capabilities.tools.expect("tools are declared");
    assert_eq!(tools.list_changed, Some(true));
}

#[test]
fn a_workbench_and_a_cloud_key_list_their_tools_side_by_side() {
    use crate::cloud::Listing;
    let both = crate::server::tool_list(&Backends {
        workbench: Some(WORKBENCH_NAMES.to_vec()),
        cloud: Some(Listing::Launch),
    });
    let names: Vec<&str> = both.iter().map(|t| t.name.as_ref()).collect();
    assert_eq!(names.len(), 31, "{names:?}");
    let mut unique = names.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), names.len(), "{names:?}");
    let b = Backends {
        workbench: Some(Vec::new()),
        cloud: Some(Listing::Read),
    };
    for n in names {
        assert!(crate::tools::known(n, &b), "{n}");
    }
}

/// A refusal says which backend refused by its reason alone, and an id says which
/// backend it belongs to by its prefix alone, so neither is read as the other's.
#[test]
fn the_backends_share_no_reason_and_no_id_prefix() {
    use crate::core::Reason;
    let workbench = [
        Reason::WorkbenchUnavailable,
        Reason::WorkbenchOutOfScope,
        Reason::ProjectChanged,
        Reason::WorkbenchError,
    ]
    .map(Reason::as_str);
    let cloud: Vec<&str> = [
        Reason::CloudUnavailable,
        Reason::CloudKeyRejected,
        Reason::PermissionDenied,
        Reason::OutOfLocalScope,
        Reason::ApprovalDenied,
        Reason::ApprovalExpired,
        Reason::ApprovalRequired,
    ]
    .map(Reason::as_str)
    .into_iter()
    .chain(cfx_cloud_wire::Reason::ALL.map(cfx_cloud_wire::Reason::as_str))
    .collect();
    for w in workbench {
        assert!(!cloud.contains(&w), "{w} is a Cloud reason too");
    }

    let mut prefixes = vec![cfx_bridge::HANDLE_PREFIX, cfx_bridge::CURSOR_PREFIX];
    prefixes.extend(cfx_cloud_wire::IdKind::ALL.map(cfx_cloud_wire::IdKind::prefix));
    // Local scans and findings, as crate::kept names them.
    prefixes.extend(["s_", "f_"]);
    for (i, a) in prefixes.iter().enumerate() {
        for b in &prefixes[i + 1..] {
            assert!(!a.starts_with(b) && !b.starts_with(a), "{a} and {b}");
        }
    }
}

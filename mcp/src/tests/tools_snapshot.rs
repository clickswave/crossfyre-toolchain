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
const PINNED: &str = "ab7a877e81faeecd4f3d208fd9fa94f4d3b4a1bf4c00615f46ac42046d60952c";

/// The same for `tools_workbench.json`.
const PINNED_WORKBENCH: &str = "0993a4467745f5cd426e4ca569e98b40569aff390b361a5593f4e54986c63b21";

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
    assert_eq!(hints("send_http_request"), (false, true, false, true));
    assert_eq!(hints("cancel_scan"), (false, false, true, false));
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
    let off = all(&Backends { workbench: None });
    assert_eq!(off.len(), 11);
    assert!(
        off.iter()
            .all(|t| t.output_schema.is_some() && t.annotations.is_some())
    );
    assert_eq!(
        all(&Backends {
            workbench: Some(Vec::new())
        })
        .len(),
        11
    );
    let every = all(&Backends {
        workbench: Some(WORKBENCH_NAMES.to_vec()),
    });
    assert_eq!(every.len(), 18);
    assert!(
        every
            .iter()
            .all(|t| t.output_schema.is_some() && t.annotations.is_some())
    );
    let some = all(&Backends {
        workbench: Some(vec!["workbench_get_scope"]),
    });
    assert_eq!(some.last().unwrap().name, "workbench_get_scope");
    assert_eq!(some.len(), 12);
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

//! The tool definitions are a contract with every client that has read them.
//!
//! A change to a name, a hint or a schema changes what a client lets a model do, so it
//! has to be made on purpose: this hash is updated in the same change as the file.

use crate::scope_file::sha256_hex;
use crate::tools::{NAMES, TARGET_DATA_TOOLS, TOOLS_JSON, UNTRUSTED_DESCRIPTION};
use serde_json::Value;

/// sha256 of `tools.json` with CRLF read as LF, so a Windows checkout agrees.
const PINNED: &str = "b58a4d9bb4f1d3665aa5889c7e4bbad9fd104dc641f362868ff3c7756fd45b24";

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
fn the_protocol_layer_reads_them() {
    let tools = crate::server::tool_list();
    assert_eq!(tools.len(), 11);
    assert!(
        tools
            .iter()
            .all(|t| t.output_schema.is_some() && t.annotations.is_some())
    );
}

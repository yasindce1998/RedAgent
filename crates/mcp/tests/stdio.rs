use std::path::Path;
use std::time::Duration;

use redagent_mcp::StdioMcpClient;

fn fake_server() -> std::path::PathBuf {
    Path::new(env!("CARGO_BIN_EXE_fake-mcp-server")).to_path_buf()
}

#[test]
fn initialize_list_and_call() {
    let mut client = StdioMcpClient::spawn(&fake_server(), &[], &[])
        .unwrap()
        .with_timeout(Duration::from_secs(10));
    let version = client.initialize().unwrap();
    assert_eq!(version, "2026-07-28");
    let tools = client.tools_list().unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, "redhands_health");
    let result = client
        .tools_call("redhands_health", serde_json::json!({}))
        .unwrap();
    assert!(!result.is_error);
    assert!(result.content.contains("Status: OK"));
}

#[test]
fn gated_tool_approval_via_input_responses() {
    use serde_json::json;

    let mut client = StdioMcpClient::spawn(&fake_server(), &[], &[])
        .unwrap()
        .with_timeout(Duration::from_secs(10));
    client.initialize().unwrap();

    // First call: the gate pauses inline with an elicitation request.
    let result = client.tools_call("gated_echo", json!({})).unwrap();
    assert_eq!(result.result_type.as_deref(), Some("input_required"));
    assert!(result.content.contains("requires operator approval"));
    let requests = result.input_requests.expect("missing inputRequests");
    let approval = &requests["approval"];
    assert_eq!(approval["type"], "elicitation/create");
    assert_eq!(approval["requestId"], "req_test");

    // Re-issue the same call with an affirmative approval. The grant is
    // scoped to this one call, so the gate lets it through.
    let approved = client
        .tools_call_with_responses(
            "gated_echo",
            json!({}),
            Some(json!({"approval": {"approved": true}})),
        )
        .unwrap();
    assert_eq!(approved.result_type, None);
    assert!(approved.input_requests.is_none());
    assert!(approved.content.contains("approved"));
}

#[test]
fn unknown_tool_is_an_error() {
    let mut client = StdioMcpClient::spawn(&fake_server(), &[], &[]).unwrap();
    client.initialize().unwrap();
    assert!(client
        .tools_call("no_such_tool", serde_json::json!({}))
        .is_err());
}

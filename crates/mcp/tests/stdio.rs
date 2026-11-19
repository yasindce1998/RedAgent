use std::path::Path;
use std::time::Duration;

use redagent_mcp::StdioMcpClient;

fn fake_server() -> std::path::PathBuf {
    Path::new(env!("CARGO_BIN_EXE_fake-mcp-server")).to_path_buf()
}

fn client(envs: &[(&str, &str)]) -> StdioMcpClient {
    StdioMcpClient::spawn(&fake_server(), &[], envs)
        .unwrap()
        .with_timeout(Duration::from_secs(10))
}

#[test]
fn initialize_list_and_call() {
    let mut client = client(&[]);
    let version = client.initialize().unwrap();
    assert_eq!(version, "2026-07-28");
    let tools = client.tools_list().unwrap();
    assert_eq!(tools.len(), 2);
    assert_eq!(tools[0].name, "redhands_health");
    let result = client
        .tools_call("redhands_health", serde_json::json!({}))
        .unwrap();
    assert!(!result.is_error);
    assert!(result.content.contains("Status: OK"));
}

#[test]
fn tool_policies_are_decoded_from_redhands_and_annotations() {
    let mut client = client(&[]);
    client.initialize().unwrap();
    let tools = client.tools_list().unwrap();
    assert!(tools[0].read_only);
    assert!(!tools[0].requires_approval);
    assert!(!tools[1].read_only);
    assert!(tools[1].requires_approval);
}

#[test]
fn gated_tool_approval_via_input_responses() {
    use serde_json::json;

    let mut client = client(&[]);
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
fn input_responses_are_omitted_unless_supplied() {
    use serde_json::Value;

    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("requests.jsonl");
    let log_path = log.to_string_lossy().into_owned();
    let mut client = client(&[("FAKE_MCP_LOG", log_path.as_str())]);
    client.initialize().unwrap();
    client
        .tools_call("gated_echo", serde_json::json!({}))
        .unwrap();
    client
        .tools_call_with_responses(
            "gated_echo",
            serde_json::json!({}),
            Some(serde_json::json!({"approval": {"approved": true}})),
        )
        .unwrap();

    let raw = std::fs::read_to_string(&log).unwrap();
    let calls: Vec<Value> = raw
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|value| value["method"] == "tools/call")
        .collect();
    assert_eq!(calls.len(), 2);
    assert!(calls[0]["params"].get("inputResponses").is_none());
    assert_eq!(
        calls[1]["params"]["inputResponses"]["approval"]["approved"],
        true
    );
}

#[test]
fn approval_grant_is_single_use() {
    use serde_json::json;

    let mut client = client(&[("FAKE_MCP_GRANT_ONCE", "1")]);
    client.initialize().unwrap();
    let grant = json!({"approval": {"approved": true}});

    let first = client.tools_call("gated_echo", json!({})).unwrap();
    assert_eq!(first.result_type.as_deref(), Some("input_required"));
    let approved = client
        .tools_call_with_responses("gated_echo", json!({}), Some(grant.clone()))
        .unwrap();
    assert_eq!(approved.result_type, None);
    // Replaying the same grant must not authorize a second call.
    let replay = client
        .tools_call_with_responses("gated_echo", json!({}), Some(grant))
        .unwrap();
    assert_eq!(replay.result_type.as_deref(), Some("input_required"));
}

#[test]
fn server_exit_is_reported_as_disconnect_not_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("requests.jsonl");
    let log_path = log.to_string_lossy().into_owned();
    let mut client = StdioMcpClient::spawn(
        &fake_server(),
        &[],
        &[
            ("FAKE_MCP_MODE", "exit_before_response"),
            ("FAKE_MCP_LOG", log_path.as_str()),
        ],
    )
    .unwrap()
    .with_timeout(Duration::from_secs(5));

    let error = client.initialize().unwrap_err().to_string();
    assert!(
        error.contains("MCP server exited"),
        "unexpected error: {error}"
    );
    assert!(!error.contains("timeout"), "unexpected error: {error}");

    // initialize() must stop trying protocol versions once the pipe closes.
    let raw = std::fs::read_to_string(&log).unwrap();
    let attempts = raw
        .lines()
        .filter(|line| line.contains("\"method\":\"initialize\""))
        .count();
    assert_eq!(attempts, 1, "initialize fallback kept retrying");
}

#[test]
fn unknown_tool_is_an_error() {
    let mut client = client(&[]);
    client.initialize().unwrap();
    assert!(client
        .tools_call("no_such_tool", serde_json::json!({}))
        .is_err());
}

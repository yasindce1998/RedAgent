//! Deterministic fake tool server for the conformance integration tests.
//!
//! Speaks newline-delimited JSON-RPC 2.0 over stdio. `FAKE_CONFORMANCE_MODE`
//! selects a deliberately broken scenario; the default is a healthy RedHands-
//! shaped server with one read-only tool and one inline-gated tool.

use std::io::{self, BufRead, Write};

use serde_json::{json, Value};

const SUPPORTED_VERSIONS: [&str; 3] = ["2026-07-28", "2025-03-26", "2024-11-05"];

fn success(id: &Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn failure(id: &Value, code: i64, message: impl Into<String>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": code, "message": message.into()}
    })
}

fn health_tool() -> Value {
    json!({
        "name": "redhands_health",
        "description": "Check RedHands health",
        "inputSchema": {"type": "object", "properties": {}},
        "x-redhands-policy": {
            "readOnly": true,
            "networkAccess": false,
            "requiresApproval": false
        },
        "annotations": {"readOnlyHint": true, "destructiveHint": false}
    })
}

fn gated_tool() -> Value {
    json!({
        "name": "gated_echo",
        "description": "Echo text after operator approval",
        "inputSchema": {"type": "object", "properties": {}},
        "x-redhands-policy": {
            "readOnly": false,
            "networkAccess": false,
            "requiresApproval": true
        },
        "annotations": {"readOnlyHint": false, "destructiveHint": true}
    })
}

fn tools_list(mode: &str) -> Value {
    match mode {
        "malformed_tools_list" => json!({"tools": "not-an-array"}),
        "invalid_tool" => json!({"tools": [{"name": "", "inputSchema": 7}]}),
        "no_gated_echo" => json!({"tools": [health_tool()], "ttlMs": 300000}),
        _ => json!({
            "tools": [health_tool(), gated_tool()],
            "ttlMs": 300000
        }),
    }
}

fn tool_call(id: &Value, params: Option<&Value>) -> Value {
    let params = params.cloned().unwrap_or(Value::Null);
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    match name {
        "redhands_health" => success(
            id,
            json!({
                "content": [{"type": "text", "text": "Status: OK"}],
                "isError": false
            }),
        ),
        "gated_echo" => {
            let approved = params
                .get("inputResponses")
                .and_then(|responses| responses.get("approval"))
                .and_then(|approval| approval.get("approved"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if approved {
                success(
                    id,
                    json!({
                        "content": [{"type": "text", "text": "echo approved"}],
                        "isError": false
                    }),
                )
            } else {
                success(
                    id,
                    json!({
                        "content": [{"type": "text", "text": "requires operator approval"}],
                        "isError": false,
                        "resultType": "input_required",
                        "inputRequests": {
                            "approval": {
                                "type": "elicitation/create",
                                "message": "Approve gated_echo?",
                                "requestId": "req_conformance"
                            }
                        }
                    }),
                )
            }
        }
        _ => failure(id, -32602, format!("unknown tool: {name}")),
    }
}

fn main() {
    let mode = std::env::var("FAKE_CONFORMANCE_MODE").unwrap_or_default();
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let Ok(message) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let Some(method) = message.get("method").and_then(Value::as_str) else {
            continue;
        };
        if method.starts_with("notifications/") {
            continue;
        }
        let Some(id) = message.get("id") else {
            continue;
        };
        let params = message.get("params");

        let response = match method {
            "initialize" => {
                let requested = params
                    .and_then(|p| p.get("protocolVersion"))
                    .and_then(Value::as_str)
                    .unwrap_or("2026-07-28");
                success(
                    id,
                    json!({
                        "protocolVersion": requested,
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "fake-tool-server", "version": "0.1.0"},
                        "protocolVersions": SUPPORTED_VERSIONS
                    }),
                )
            }
            "tools/list" => {
                if mode == "garbage_line" {
                    let _ = writeln!(stdout, "this is not JSON");
                    let _ = stdout.flush();
                    continue;
                }
                success(id, tools_list(&mode))
            }
            "tools/call" => tool_call(id, params),
            _ => failure(id, -32601, format!("unknown method: {method}")),
        };
        let _ = writeln!(stdout, "{response}");
        let _ = stdout.flush();
    }
}

//! Tiny deterministic MCP server used by the client integration tests.
//! Speaks newline-delimited JSON-RPC 2.0 over stdio. Test scenarios are driven
//! by `FAKE_MCP_*` environment variables; the default behaviour is a healthy
//! server with one plain tool and one approval-gated tool.

use std::fs::OpenOptions;
use std::io::{self, BufRead, Write};

use serde_json::{json, Value};

fn log_request(log: Option<&str>, line: &str) {
    if let Some(path) = log {
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(file, "{line}");
        }
    }
}

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let log = std::env::var("FAKE_MCP_LOG").ok();
    let exit_before_response =
        std::env::var("FAKE_MCP_MODE").ok().as_deref() == Some("exit_before_response");
    let grant_once = std::env::var("FAKE_MCP_GRANT_ONCE").is_ok();
    let mut grant_used = false;

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) => line,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        log_request(log.as_deref(), &line);
        let message: Value = match serde_json::from_str(&line) {
            Ok(message) => message,
            Err(_) => continue,
        };
        let method = message.get("method").and_then(Value::as_str).unwrap_or("");
        if method.starts_with("notifications/") {
            continue;
        }
        if exit_before_response {
            let _ = stdout.flush();
            std::process::exit(0);
        }
        let Some(id) = message.get("id").cloned() else {
            continue;
        };
        let result = match method {
            "initialize" => {
                let version = message
                    .get("params")
                    .and_then(|p| p.get("protocolVersion"))
                    .and_then(Value::as_str)
                    .unwrap_or("2026-07-28");
                json!({
                    "protocolVersion": version,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "fake-redhands", "version": "v0.6.3"},
                    "protocolVersions": ["2026-07-28", "2025-03-26", "2024-11-05"]
                })
            }
            "tools/list" => json!({
                "tools": [
                    {
                        "name": "redhands_health",
                        "description": "Check RedHands health",
                        "inputSchema": {"type": "object", "properties": {}},
                        "x-redhands-policy": {
                            "readOnly": true,
                            "networkAccess": false,
                            "requiresPrivileges": false,
                            "requiresApproval": false,
                            "retrySafe": true,
                            "cacheable": false
                        },
                        "annotations": {
                            "readOnlyHint": true,
                            "destructiveHint": false,
                            "idempotentHint": true,
                            "openWorldHint": false
                        }
                    },
                    {
                        "name": "gated_echo",
                        "description": "Echo text after operator approval",
                        "inputSchema": {"type": "object", "properties": {}},
                        "x-redhands-policy": {
                            "readOnly": false,
                            "networkAccess": false,
                            "requiresPrivileges": false,
                            "requiresApproval": true,
                            "retrySafe": false,
                            "cacheable": false
                        },
                        "annotations": {
                            "readOnlyHint": false,
                            "destructiveHint": true,
                            "idempotentHint": false,
                            "openWorldHint": false
                        }
                    }
                ],
                "ttlMs": 300000
            }),
            "tools/call" => {
                let params = message.get("params");
                let name = params
                    .and_then(|p| p.get("name"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if name == "gated_echo" {
                    let approved = params
                        .and_then(|p| p.get("inputResponses"))
                        .and_then(|r| r.get("approval"))
                        .and_then(|a| a.get("approved"))
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    if approved && !(grant_once && grant_used) {
                        grant_used = true;
                        json!({
                            "content": [{"type": "text", "text": "approved"}],
                            "isError": false
                        })
                    } else {
                        json!({
                            "content": [{
                                "type": "text",
                                "text": "requires operator approval"
                            }],
                            "isError": false,
                            "resultType": "input_required",
                            "inputRequests": {
                                "approval": {
                                    "type": "elicitation/create",
                                    "message": "Approve gated_echo?",
                                    "requestId": if grant_used { "req_test_2" } else { "req_test" }
                                }
                            }
                        })
                    }
                } else if name != "redhands_health" {
                    let response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {"code": -32602, "message": format!("unknown tool: {name}")}
                    });
                    let _ = writeln!(stdout, "{}", response);
                    let _ = stdout.flush();
                    continue;
                } else {
                    json!({
                        "content": [{
                            "type": "text",
                            "text": "## RedHands Health Check\n\n### Status: OK\n"
                        }],
                        "isError": false
                    })
                }
            }
            _ => {
                let response = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {"code": -32601, "message": format!("unknown method: {method}")}
                });
                let _ = writeln!(stdout, "{}", response);
                let _ = stdout.flush();
                continue;
            }
        };
        let response = json!({"jsonrpc": "2.0", "id": id, "result": result});
        let _ = writeln!(stdout, "{}", response);
        let _ = stdout.flush();
    }
}

//! Tiny deterministic MCP server used by the client integration tests.
//! Speaks newline-delimited JSON-RPC 2.0 over stdio.

use std::io::{self, BufRead, Write};

use serde_json::{json, Value};

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) => line,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        let message: Value = match serde_json::from_str(&line) {
            Ok(message) => message,
            Err(_) => continue,
        };
        let method = message.get("method").and_then(Value::as_str).unwrap_or("");
        if method.starts_with("notifications/") {
            continue;
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
                    "capabilities": {},
                    "serverInfo": {"name": "fake-redhands", "version": "v0.6.3"}
                })
            }
            "tools/list" => json!({
                "tools": [{
                    "name": "redhands_health",
                    "description": "Check RedHands health",
                    "inputSchema": {"type": "object", "properties": {}}
                }]
            }),
            "tools/call" => {
                let name = message
                    .get("params")
                    .and_then(|p| p.get("name"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if name != "redhands_health" {
                    let response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {"code": -32602, "message": format!("unknown tool: {name}")}
                    });
                    let _ = writeln!(stdout, "{}", response);
                    let _ = stdout.flush();
                    continue;
                }
                json!({
                    "content": [{
                        "type": "text",
                        "text": "## RedHands Health Check\n\n### Status: OK\n"
                    }],
                    "isError": false
                })
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

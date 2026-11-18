use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::jsonrpc::{parse_response, Notification, Request, JSONRPC_VERSION};

/// Protocol versions attempted in order. RedHands serves both the modern
/// 2026-07-28 revision and the legacy 2025-03-26 / 2024-11-05 handshakes.
pub const PROTOCOL_VERSIONS: [&str; 3] = ["2026-07-28", "2025-03-26", "2024-11-05"];
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Deserialize)]
pub struct ToolInfo {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default, alias = "inputSchema")]
    pub input_schema: Value,
}

#[derive(Debug, Clone)]
pub struct ToolCallResult {
    pub content: String,
    pub is_error: bool,
    /// Extended result shape, e.g. `"input_required"` when a gated tool
    /// pauses the call pending operator approval.
    pub result_type: Option<String>,
    /// Elicitation requests keyed by input name (e.g. `"approval"`).
    pub input_requests: Option<serde_json::Value>,
}

/// A synchronous MCP client over a child process' stdio pipes.
pub struct StdioMcpClient {
    child: Child,
    writer: std::io::BufWriter<ChildStdin>,
    reader: Receiver<String>,
    next_id: u64,
    timeout: Duration,
    pub negotiated_version: Option<String>,
}

impl StdioMcpClient {
    pub fn spawn(program: &Path, args: &[&str], envs: &[(&str, &str)]) -> Result<Self> {
        let mut command = Command::new(program);
        command
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .envs(envs.iter().copied());
        let mut child = command
            .spawn()
            .with_context(|| format!("spawning MCP server {}", program.display()))?;
        let stdin = child.stdin.take().context("child has no stdin")?;
        let stdout = child.stdout.take().context("child has no stdout")?;
        let (tx, reader) = mpsc::channel::<String>();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                match line {
                    Ok(line) => {
                        if tx.send(line).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            child,
            writer: std::io::BufWriter::new(stdin),
            reader,
            next_id: 1,
            timeout: DEFAULT_TIMEOUT,
            negotiated_version: None,
        })
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Perform the initialize handshake, trying modern and legacy protocol
    /// versions in order. Returns the negotiated version.
    pub fn initialize(&mut self) -> Result<String> {
        let mut last_error = None;
        for version in PROTOCOL_VERSIONS {
            let params = json!({
                "protocolVersion": version,
                "capabilities": {},
                "clientInfo": {"name": "redagent", "version": env!("CARGO_PKG_VERSION")}
            });
            match self.request("initialize", params) {
                Ok(result) => {
                    let negotiated = result
                        .get("protocolVersion")
                        .and_then(Value::as_str)
                        .unwrap_or(version)
                        .to_string();
                    self.negotiated_version = Some(negotiated.clone());
                    // MCP clients acknowledge the handshake with a notification.
                    self.notify("notifications/initialized", json!({}))?;
                    return Ok(negotiated);
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow!("all protocol versions failed")))
    }

    pub fn tools_list(&mut self) -> Result<Vec<ToolInfo>> {
        let result = self.request("tools/list", json!({}))?;
        let tools = result
            .get("tools")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("tools/list response has no tools array"))?;
        serde_json::from_value(Value::Array(tools.clone())).context("decoding tools/list response")
    }

    pub fn tools_call(&mut self, name: &str, arguments: Value) -> Result<ToolCallResult> {
        self.tools_call_with_responses(name, arguments, None)
    }

    /// Issue a `tools/call`, optionally answering inline elicitation requests.
    ///
    /// RedHands returns gated-tool approvals inline (no server-initiated
    /// request): the first call carries `resultType: "input_required"` and an
    /// `inputRequests` map. Re-issuing the same call with the matching
    /// `inputResponses` grants approval for that one call only.
    pub fn tools_call_with_responses(
        &mut self,
        name: &str,
        arguments: Value,
        input_responses: Option<Value>,
    ) -> Result<ToolCallResult> {
        let mut params = json!({"name": name, "arguments": arguments});
        if let Some(responses) = input_responses {
            params["inputResponses"] = responses;
        }
        let result = self.request("tools/call", params)?;
        let is_error = result
            .get("isError")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let result_type = result
            .get("resultType")
            .and_then(Value::as_str)
            .map(str::to_string);
        let input_requests = result.get("inputRequests").cloned();
        let mut content = String::new();
        if let Some(blocks) = result.get("content").and_then(Value::as_array) {
            for block in blocks {
                if block.get("type").and_then(Value::as_str) == Some("text") {
                    if let Some(text) = block.get("text").and_then(Value::as_str) {
                        content.push_str(text);
                        content.push('\n');
                    }
                }
            }
        }
        Ok(ToolCallResult {
            content,
            is_error,
            result_type,
            input_requests,
        })
    }

    fn notify(&mut self, method: &str, params: Value) -> Result<()> {
        let notification = Notification {
            jsonrpc: JSONRPC_VERSION,
            method,
            params,
        };
        self.write_line(&serde_json::to_string(&notification)?)
    }

    fn request(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        let request = Request {
            jsonrpc: JSONRPC_VERSION,
            id,
            method,
            params,
        };
        self.write_line(&serde_json::to_string(&request)?)?;

        loop {
            let line = self
                .reader
                .recv_timeout(self.timeout)
                .with_context(|| format!("timeout waiting for response to {method}"))?;
            // Servers may emit logs or notifications on stdout; ignore them.
            let response = match parse_response(&line) {
                Ok(response) => response,
                Err(_) => continue,
            };
            if response.id != Some(id) {
                continue;
            }
            if let Some(error) = response.error {
                return Err(anyhow!(
                    "MCP {method} error {}: {}",
                    error.code,
                    error.message
                ));
            }
            return Ok(response.result.unwrap_or(Value::Null));
        }
    }

    fn write_line(&mut self, line: &str) -> Result<()> {
        self.writer.write_all(line.as_bytes())?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        Ok(())
    }
}

impl Drop for StdioMcpClient {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

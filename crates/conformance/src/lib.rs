//! Black-box conformance checks for tool servers described by a
//! [`ToolServerManifest`].
//!
//! The runner spawns the server binary, speaks newline-delimited JSON-RPC 2.0
//! over its stdio pipes and reports each probe as a named [`Check`]. It never
//! panics on malformed responses: server misbehaviour is recorded as a failed
//! check in an otherwise successful [`ConformanceReport`].

use std::fmt::{self, Write as FmtWrite};
use std::io::{BufRead, BufReader, BufWriter, ErrorKind, Write as IoWrite};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::Duration;

use anyhow::{Context, Result};
use redagent_contract::{normalize_tool, ApprovalSemantics, ToolServerManifest};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const CHECK_INITIALIZE: &str = "initialize negotiates a supported protocolVersion";
const CHECK_TOOLS_LIST: &str = "tools/list returns a non-empty tools array";
const CHECK_NORMALIZE: &str = "tools normalize under the manifest";
const CHECK_READ_ONLY: &str = "at least one tool is read-only";
const CHECK_READ_ONLY_CALL: &str = "tools/call on a read-only tool returns content";
const CHECK_UNKNOWN_TOOL: &str = "unknown tool returns a JSON-RPC error";
const CHECK_GATED_ECHO: &str = "gated_echo inline approval flow";

/// A single named conformance probe.
#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

/// The complete set of probes run against one tool server.
#[derive(Debug, Clone, Serialize)]
pub struct ConformanceReport {
    pub server: String,
    pub passed: bool,
    pub checks: Vec<Check>,
}

fn check(name: &str, passed: bool, detail: impl Into<String>) -> Check {
    Check {
        name: name.to_string(),
        passed,
        detail: detail.into(),
    }
}

#[derive(Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'static str,
    id: u64,
    method: &'a str,
    params: Value,
}

#[derive(Serialize)]
struct RpcNotification<'a> {
    jsonrpc: &'static str,
    method: &'a str,
    params: Value,
}

#[derive(Deserialize)]
struct RpcErrorBody {
    code: i64,
    message: String,
}

#[derive(Deserialize)]
struct RpcResponse {
    jsonrpc: String,
    id: Option<u64>,
    result: Option<Value>,
    error: Option<RpcErrorBody>,
}

/// Why a request did not produce a usable result. A JSON-RPC error is kept
/// distinct from transport problems so the "unknown tool" probe can demand a
/// real protocol error rather than, say, a timeout.
#[derive(Debug)]
enum RequestFailure {
    Rpc { code: i64, message: String },
    Transport(String),
}

impl fmt::Display for RequestFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rpc { code, message } => write!(formatter, "JSON-RPC error {code}: {message}"),
            Self::Transport(detail) => formatter.write_str(detail),
        }
    }
}

/// Minimal line-oriented JSON-RPC client over a child process' stdio.
struct LineClient {
    child: Child,
    writer: BufWriter<ChildStdin>,
    reader: Receiver<String>,
    next_id: u64,
    timeout: Duration,
}

impl LineClient {
    fn spawn(
        binary: &Path,
        args: &[&str],
        envs: &[(&str, &str)],
        timeout: Duration,
    ) -> Result<Self> {
        let mut command = Command::new(binary);
        command
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .envs(envs.iter().copied());
        let mut child = command
            .spawn()
            .with_context(|| format!("spawning tool server {}", binary.display()))?;
        let stdin = child.stdin.take().context("child has no stdin")?;
        let stdout = child.stdout.take().context("child has no stdout")?;
        let (sender, reader) = mpsc::channel::<String>();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                match line {
                    Ok(line) => {
                        if sender.send(line).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            child,
            writer: BufWriter::new(stdin),
            reader,
            next_id: 1,
            timeout,
        })
    }

    fn request(
        &mut self,
        method: &str,
        params: Value,
    ) -> std::result::Result<Value, RequestFailure> {
        let id = self.next_id;
        self.next_id += 1;
        let request = RpcRequest {
            jsonrpc: "2.0",
            id,
            method,
            params,
        };
        let line = serde_json::to_string(&request)
            .map_err(|error| RequestFailure::Transport(format!("encoding request: {error}")))?;
        self.write_line(&line)?;

        loop {
            let line = match self.reader.recv_timeout(self.timeout) {
                Ok(line) => line,
                Err(RecvTimeoutError::Timeout) => {
                    return Err(RequestFailure::Transport(format!(
                        "timeout after {:?} waiting for {method}",
                        self.timeout
                    )))
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(RequestFailure::Transport(format!(
                        "server closed stdout while waiting for {method}"
                    )))
                }
            };
            // Logs, notifications and malformed lines are ignored rather than
            // treated as fatal; the matching response may still be coming.
            let response: RpcResponse = match serde_json::from_str(&line) {
                Ok(response) => response,
                Err(_) => continue,
            };
            if response.jsonrpc != "2.0" || response.id != Some(id) {
                continue;
            }
            if let Some(error) = response.error {
                return Err(RequestFailure::Rpc {
                    code: error.code,
                    message: error.message,
                });
            }
            return Ok(response.result.unwrap_or(Value::Null));
        }
    }

    fn notify(&mut self, method: &str, params: Value) -> std::result::Result<(), RequestFailure> {
        let notification = RpcNotification {
            jsonrpc: "2.0",
            method,
            params,
        };
        let line = serde_json::to_string(&notification).map_err(|error| {
            RequestFailure::Transport(format!("encoding notification: {error}"))
        })?;
        self.write_line(&line)
    }

    fn write_line(&mut self, line: &str) -> std::result::Result<(), RequestFailure> {
        let write = (|| -> std::io::Result<()> {
            self.writer.write_all(line.as_bytes())?;
            self.writer.write_all(b"\n")?;
            self.writer.flush()
        })();
        match write {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == ErrorKind::BrokenPipe => Err(RequestFailure::Transport(
                format!("server closed stdin while sending request: {error}"),
            )),
            Err(error) => Err(RequestFailure::Transport(format!(
                "writing request to server: {error}"
            ))),
        }
    }
}

impl Drop for LineClient {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Run the full conformance suite against a tool server binary.
///
/// Spawning failures are returned as errors. All protocol-level problems
/// (timeouts, JSON-RPC errors, malformed tool metadata, unexpected responses)
/// are captured as failed checks in the returned report.
pub fn run_conformance(
    binary: &Path,
    args: &[&str],
    envs: &[(&str, &str)],
    manifest: &ToolServerManifest,
    timeout: Duration,
) -> Result<ConformanceReport> {
    let mut client = LineClient::spawn(binary, args, envs, timeout)?;
    let mut checks = Vec::with_capacity(7);

    // 1. initialize handshake.
    let mut initialized = false;
    let mut init_detail = String::from("server did not respond to any declared protocol version");
    for version in &manifest.protocol_versions {
        let params = json!({
            "protocolVersion": version,
            "capabilities": {"tools": {}},
            "clientInfo": {"name": "redagent-conformance", "version": env!("CARGO_PKG_VERSION")}
        });
        match client.request("initialize", params) {
            Ok(result) => match result.get("protocolVersion").and_then(Value::as_str) {
                Some(reported) if manifest.protocol_versions.iter().any(|v| v == reported) => {
                    initialized = true;
                    init_detail = format!("negotiated protocolVersion {reported}");
                }
                Some(reported) => {
                    init_detail = format!("server reported unsupported protocolVersion {reported}");
                }
                None => {
                    init_detail = "initialize response omitted protocolVersion".to_string();
                }
            },
            Err(failure) => {
                init_detail = format!("initialize ({version}) failed: {failure}");
            }
        }
        if initialized {
            let _ = client.notify("notifications/initialized", json!({}));
            break;
        }
    }
    checks.push(check(CHECK_INITIALIZE, initialized, init_detail));

    // 2. tools/list shape.
    let mut listed_tools: Vec<Value> = Vec::new();
    let (list_ok, list_detail) = match client.request("tools/list", json!({})) {
        Ok(result) => match result.get("tools").and_then(Value::as_array) {
            Some(tools) if !tools.is_empty() => {
                listed_tools = tools.clone();
                (
                    true,
                    format!("server listed {} tool(s)", listed_tools.len()),
                )
            }
            Some(_) => (
                false,
                "tools/list returned an empty tools array".to_string(),
            ),
            None => (
                false,
                "tools/list response has no `tools` array".to_string(),
            ),
        },
        Err(failure) => (false, format!("tools/list failed: {failure}")),
    };
    checks.push(check(CHECK_TOOLS_LIST, list_ok, list_detail));

    // 3. tool metadata and normalization.
    let mut normalized = Vec::new();
    let mut problems = Vec::new();
    for (index, raw) in listed_tools.iter().enumerate() {
        let name = raw.get("name").and_then(Value::as_str).unwrap_or("");
        let mut tool_problems = Vec::new();
        if name.trim().is_empty() {
            tool_problems.push("empty or missing name".to_string());
        }
        if raw
            .get("inputSchema")
            .or_else(|| raw.get("input_schema"))
            .is_none_or(|schema| !schema.is_object())
        {
            tool_problems.push("inputSchema is not an object".to_string());
        }
        if tool_problems.is_empty() {
            match normalize_tool(raw, manifest) {
                Ok(tool) => normalized.push(tool),
                Err(error) => tool_problems.push(format!("normalization error: {error:#}")),
            }
        }
        if !tool_problems.is_empty() {
            let label = if name.is_empty() { "<unnamed>" } else { name };
            problems.push(format!(
                "tool[{index}] ({label}): {}",
                tool_problems.join("; ")
            ));
        }
    }
    let normalize_ok = list_ok && problems.is_empty() && normalized.len() == listed_tools.len();
    let normalize_detail = if !list_ok {
        "no tools available; tools/list did not return a tools array".to_string()
    } else if problems.is_empty() {
        format!(
            "all {} tool(s) have a name, an object inputSchema and normalized cleanly",
            normalized.len()
        )
    } else {
        format!(
            "{} tool(s) failed validation: {}",
            problems.len(),
            problems.join(" | ")
        )
    };
    checks.push(check(CHECK_NORMALIZE, normalize_ok, normalize_detail));

    // 4. read-only discovery (when the manifest declares such pointers).
    let (read_only_ok, read_only_detail) = if manifest.policy_paths.read_only.is_empty() {
        (
            true,
            "manifest declares no read-only pointers; check skipped".to_string(),
        )
    } else {
        let names: Vec<&str> = normalized
            .iter()
            .filter(|tool| tool.read_only)
            .map(|tool| tool.name.as_str())
            .collect();
        if names.is_empty() {
            (
                false,
                format!(
                    "no tool is read-only under pointers {:?}; absent signals fail closed",
                    manifest.policy_paths.read_only
                ),
            )
        } else {
            (true, format!("read-only tool(s): {}", names.join(", ")))
        }
    };
    checks.push(check(CHECK_READ_ONLY, read_only_ok, read_only_detail));

    // 5. call the first read-only tool.
    let (call_ok, call_detail) = match normalized.iter().find(|tool| tool.read_only) {
        None => (
            true,
            "no read-only tool was listed; check skipped".to_string(),
        ),
        Some(tool) => {
            match client.request("tools/call", json!({"name": tool.name, "arguments": {}})) {
                Ok(result) => match result.get("content").and_then(Value::as_array) {
                    Some(blocks) => (
                        true,
                        format!(
                            "tools/call `{}` returned a content array with {} block(s)",
                            tool.name,
                            blocks.len()
                        ),
                    ),
                    None => (
                        false,
                        format!("tools/call `{}` response had no content array", tool.name),
                    ),
                },
                Err(failure) => (
                    false,
                    format!("tools/call `{}` failed: {failure}", tool.name),
                ),
            }
        }
    };
    checks.push(check(CHECK_READ_ONLY_CALL, call_ok, call_detail));

    // 6. an unknown tool must produce a JSON-RPC error (not a timeout or a
    // successful result). Pick a name that cannot collide with a listed tool.
    let mut unknown_name = "__redagent_conformance_unknown_tool__".to_string();
    while listed_tools
        .iter()
        .any(|tool| tool.get("name").and_then(Value::as_str) == Some(unknown_name.as_str()))
    {
        unknown_name.push('_');
    }
    let (unknown_ok, unknown_detail) =
        match client.request("tools/call", json!({"name": unknown_name, "arguments": {}})) {
            Err(RequestFailure::Rpc { code, message }) => (
                true,
                format!("unknown tool rejected with JSON-RPC error {code}: {message}"),
            ),
            Err(failure) => (
                false,
                format!("unknown tool produced no JSON-RPC error: {failure}"),
            ),
            Ok(result) => (
                false,
                format!(
                    "unknown tool unexpectedly succeeded: {}",
                    summarize(&result)
                ),
            ),
        };
    checks.push(check(CHECK_UNKNOWN_TOOL, unknown_ok, unknown_detail));

    // 7. inline approval flow for gated_echo.
    let (gated_ok, gated_detail) = if manifest.approval != ApprovalSemantics::InlineInputRequests {
        (
            true,
            format!(
                "manifest approval semantics is {:?}; check skipped",
                manifest.approval
            ),
        )
    } else if !normalized.iter().any(|tool| tool.name == "gated_echo") {
        (
            true,
            "server does not advertise gated_echo; check skipped".to_string(),
        )
    } else {
        match client.request("tools/call", json!({"name": "gated_echo", "arguments": {}})) {
            Err(failure) => (false, format!("initial gated_echo call failed: {failure}")),
            Ok(result) => {
                let result_type = result
                    .get("resultType")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let has_approval_request = result
                    .get("inputRequests")
                    .and_then(|requests| requests.get("approval"))
                    .is_some_and(Value::is_object);
                if result_type != "input_required" || !has_approval_request {
                    (
                        false,
                        format!(
                            "expected resultType=input_required and inputRequests.approval, got resultType={result_type:?} with approval request={has_approval_request}"
                        ),
                    )
                } else {
                    let approved = json!({
                        "name": "gated_echo",
                        "arguments": {},
                        "inputResponses": {"approval": {"approved": true}}
                    });
                    match client.request("tools/call", approved) {
                        Ok(final_result) => {
                            let final_type = final_result
                                .get("resultType")
                                .and_then(Value::as_str)
                                .unwrap_or("");
                            let has_content = final_result
                                .get("content")
                                .and_then(Value::as_array)
                                .is_some();
                            if final_type == "input_required" {
                                (
                                    false,
                                    "gated_echo still requested input after approval".to_string(),
                                )
                            } else if !has_content {
                                (
                                    false,
                                    "approved gated_echo call had no content array".to_string(),
                                )
                            } else {
                                (
                                    true,
                                    "gated_echo requested inline approval and succeeded after approval"
                                        .to_string(),
                                )
                            }
                        }
                        Err(failure) => {
                            (false, format!("approved gated_echo call failed: {failure}"))
                        }
                    }
                }
            }
        }
    };
    checks.push(check(CHECK_GATED_ECHO, gated_ok, gated_detail));

    let passed = checks.iter().all(|value| value.passed);
    Ok(ConformanceReport {
        server: manifest.name.clone(),
        passed,
        checks,
    })
}

/// Short, single-line rendering of a response value for failure details.
fn summarize(value: &Value) -> String {
    let text = value.to_string();
    if text.chars().count() <= 200 {
        text
    } else {
        let shortened: String = text.chars().take(200).collect();
        format!("{shortened}...")
    }
}

/// Render a report as a Markdown checklist with a final verdict.
pub fn render_report(report: &ConformanceReport) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "# Conformance report: {}", report.server);
    let _ = writeln!(output);
    for check in &report.checks {
        let mark = if check.passed { 'x' } else { ' ' };
        let _ = writeln!(output, "- [{mark}] **{}** — {}", check.name, check.detail);
    }
    let passed = report.checks.iter().filter(|check| check.passed).count();
    let verdict = if report.passed { "PASS" } else { "FAIL" };
    let _ = writeln!(output);
    let _ = writeln!(
        output,
        "**Verdict: {verdict}** — {passed}/{} checks passed",
        report.checks.len()
    );
    output
}

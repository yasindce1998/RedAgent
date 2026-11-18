//! Wiring for Phase 0: ledger → planner → guard → MCP → ledger → report.
//! There is exactly one place where the system is assembled.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use redagent_agent::{DeterministicPlanner, Planner};
use redagent_core::{render_markdown, EngagementView, EventBody, Ledger};
use redagent_guard::Policy;
use redagent_mcp::{StdioMcpClient, ToolCallResult};
use serde_json::Value;

pub const DEFAULT_REDHANDS_VERSION: &str = "v0.6.3";

#[derive(Debug, Clone)]
pub struct Config {
    pub goal: String,
    pub redhands_binary: PathBuf,
    pub ledger_path: PathBuf,
    pub redhands_version: String,
    pub max_tool_calls: usize,
    pub allowed_tools: Vec<String>,
}

impl Config {
    pub fn new(goal: impl Into<String>, redhands_binary: PathBuf, ledger_path: PathBuf) -> Self {
        Self {
            goal: goal.into(),
            redhands_binary,
            ledger_path,
            redhands_version: DEFAULT_REDHANDS_VERSION.to_string(),
            max_tool_calls: 8,
            allowed_tools: vec!["redhands_health".to_string()],
        }
    }
}

/// Abstraction over the MCP server so the engine can be unit-tested without
/// spawning a process.
pub trait ToolExecutor {
    fn initialize(&mut self) -> Result<String>;
    fn list_tools(&mut self) -> Result<Vec<String>>;
    fn call(&mut self, tool: &str, arguments: Value) -> Result<ToolCallResult>;
}

pub struct McpExecutor(StdioMcpClient);

impl ToolExecutor for McpExecutor {
    fn initialize(&mut self) -> Result<String> {
        self.0.initialize()
    }

    fn list_tools(&mut self) -> Result<Vec<String>> {
        Ok(self
            .0
            .tools_list()?
            .into_iter()
            .map(|tool| tool.name)
            .collect())
    }

    fn call(&mut self, tool: &str, arguments: Value) -> Result<ToolCallResult> {
        self.0.tools_call(tool, arguments)
    }
}

/// Spawn the pinned Go tool plane over stdio. All state files are placed next
/// to the ledger so a developer's working directory is never polluted.
pub fn spawn_executor(config: &Config) -> Result<McpExecutor> {
    let ledger_dir = config
        .ledger_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    // Phase 0 exposes exactly one tool: the health probe. Redirect every
    // state directory next to the ledger so the developer's cwd stays clean.
    let path = |name: &str| ledger_dir.join(name).to_string_lossy().into_owned();
    let env: Vec<(&str, String)> = vec![
        ("REDHANDS_TRANSPORT", "stdio".to_string()),
        ("REDHANDS_AUTH", "none".to_string()),
        ("REDHANDS_TOOLSETS", "health".to_string()),
        ("REDHANDS_AUDIT_FILE", path("redhands-audit.jsonl")),
        ("REDHANDS_TARGETDB_FILE", path("redhands-targetdb.json")),
        ("REDHANDS_LOOT_DIR", path("loot")),
        ("REDHANDS_EVIDENCE_DIR", path("evidence")),
        ("REDHANDS_ENGAGEMENT_DIR", path("engagements")),
        ("REDHANDS_WORKFLOW_STATE_DIR", path("workflow_state")),
        ("REDHANDS_PLUGINS_DIR", path("plugins")),
    ];
    let env_refs: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let client = StdioMcpClient::spawn(&config.redhands_binary, &[], &env_refs)?;
    Ok(McpExecutor(client))
}

/// Run one engagement. Errors are recorded in the ledger as aborts so the
/// audit trail explains why a run ended.
pub fn run(config: &Config) -> Result<EngagementView> {
    let mut executor = spawn_executor(config)?;
    run_with(config, &mut executor)
}

pub fn run_with<E: ToolExecutor>(config: &Config, executor: &mut E) -> Result<EngagementView> {
    let ledger = Ledger::open(&config.ledger_path)?;
    ledger.append(&EventBody::EngagementStarted {
        goal: config.goal.clone(),
        redhands_version: config.redhands_version.clone(),
    })?;

    let result = execute(config, &ledger, executor);
    if let Err(error) = &result {
        ledger.append(&EventBody::EngagementAborted {
            reason: error.to_string(),
        })?;
    }
    result?;
    load_view(&config.ledger_path)
}

fn execute<E: ToolExecutor>(config: &Config, ledger: &Ledger, executor: &mut E) -> Result<()> {
    executor.initialize().context("MCP initialize failed")?;
    let available = executor.list_tools().context("tools/list failed")?;
    let intents = DeterministicPlanner.plan(&config.goal, &available)?;
    let policy = Policy::new(config.allowed_tools.clone(), config.max_tool_calls);
    let mut findings = 0usize;

    for intent in &intents {
        ledger.append(&EventBody::IntentCreated {
            id: intent.id.clone(),
            title: intent.title.clone(),
            tool: intent.tool.clone(),
            arguments: intent.arguments.clone(),
        })?;

        let decision = policy.check(&intent.tool, findings);
        ledger.append(&EventBody::GuardDecision {
            intent_id: intent.id.clone(),
            allowed: decision.allowed,
            reason: decision.reason.clone(),
        })?;
        if !decision.allowed {
            return Err(anyhow!("guard denied '{}': {}", intent.id, decision.reason));
        }

        let call = executor.call(&intent.tool, intent.arguments.clone())?;
        let call_event = ledger.append(&EventBody::ToolCallCompleted {
            intent_id: intent.id.clone(),
            tool: intent.tool.clone(),
            content: call.content,
            is_error: call.is_error,
        })?;
        if call.is_error {
            return Err(anyhow!("tool '{}' reported an error", intent.tool));
        }

        ledger.append(&EventBody::FindingRecorded {
            id: "finding-1".to_string(),
            title: format!("RedHands health verified ({})", call_event.seq),
            severity: "info".to_string(),
            evidence_seq: call_event.seq,
        })?;
        findings += 1;
    }

    ledger.append(&EventBody::EngagementCompleted { findings })?;
    Ok(())
}

pub fn load_view(ledger_path: &Path) -> Result<EngagementView> {
    let ledger = Ledger::open(ledger_path)?;
    ledger
        .verify_chain()
        .context("ledger integrity check failed")?;
    Ok(redagent_core::projections::project(&ledger.events()?))
}

pub fn report_markdown(ledger_path: &Path) -> Result<String> {
    Ok(render_markdown(&load_view(ledger_path)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::tempdir;

    struct MockExecutor {
        calls: Vec<String>,
    }

    impl ToolExecutor for MockExecutor {
        fn initialize(&mut self) -> Result<String> {
            Ok("2026-07-28".to_string())
        }
        fn list_tools(&mut self) -> Result<Vec<String>> {
            Ok(vec!["redhands_health".to_string()])
        }
        fn call(&mut self, tool: &str, _arguments: Value) -> Result<ToolCallResult> {
            self.calls.push(tool.to_string());
            Ok(ToolCallResult {
                content: "### Status: OK".to_string(),
                is_error: false,
                result_type: None,
                input_requests: None,
            })
        }
    }

    #[test]
    fn full_loop_end_to_end_with_mock() {
        let dir = tempdir().unwrap();
        let config = Config::new(
            "health check",
            PathBuf::from("unused"),
            dir.path().join("engagement.db"),
        );
        let mut executor = MockExecutor { calls: Vec::new() };
        let view = run_with(&config, &mut executor).unwrap();
        assert!(view.completed);
        assert_eq!(view.findings.len(), 1);
        assert_eq!(executor.calls, vec!["redhands_health"]);
        assert!(report_markdown(&config.ledger_path)
            .unwrap()
            .contains("Status: OK"));
    }

    #[test]
    fn denied_tool_aborts_and_is_recorded() {
        let dir = tempdir().unwrap();
        let mut config = Config::new(
            "health check",
            PathBuf::from("unused"),
            dir.path().join("denied.db"),
        );
        config.allowed_tools = vec!["nmap_port_scan".to_string()];
        let mut executor = MockExecutor { calls: Vec::new() };
        assert!(run_with(&config, &mut executor).is_err());
        assert!(executor.calls.is_empty());
        let view = load_view(&config.ledger_path).unwrap();
        assert!(view.abort_reason.unwrap().contains("guard denied"));
    }
}

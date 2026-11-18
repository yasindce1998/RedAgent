//! Wiring for Phase 1: ledger → planner → guard → MCP (with approval
//! elicitation) → verifier → ledger → report. One assembly point.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use redagent_agent::{DeterministicPlanner, Intent, LlmPlanner, Planner, ToolDescriptor};
use redagent_core::{render_markdown, EngagementView, EventBody, Ledger};
use redagent_guard::Policy;
use redagent_llm::LlmClient;
use redagent_mcp::{StdioMcpClient, ToolCallResult};
use serde_json::Value;

pub const DEFAULT_REDHANDS_VERSION: &str = "v0.6.3";
pub const DEFAULT_LLM_BASE_URL: &str = "https://api.servicesessentials.ibm.com/v1";
pub const DEFAULT_LLM_MODEL: &str = "ibm/granite-4-h-small";

#[derive(Debug, Clone, PartialEq)]
pub enum PlannerMode {
    Deterministic,
    Llm,
}

#[derive(Debug, Clone)]
pub struct LlmConfig {
    pub base_url: String,
    pub api_key: String,
    pub model: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ApprovalMode {
    Deny,
    ApproveAll,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub goal: String,
    pub redhands_binary: PathBuf,
    pub ledger_path: PathBuf,
    pub redhands_version: String,
    pub max_tool_calls: usize,
    pub max_intents: usize,
    pub allowed_tools: Vec<String>,
    pub planner_mode: PlannerMode,
    pub llm: Option<LlmConfig>,
    pub approval_mode: ApprovalMode,
}

impl Config {
    pub fn new(goal: impl Into<String>, redhands_binary: PathBuf, ledger_path: PathBuf) -> Self {
        Self {
            goal: goal.into(),
            redhands_binary,
            ledger_path,
            redhands_version: DEFAULT_REDHANDS_VERSION.to_string(),
            max_tool_calls: 8,
            max_intents: 6,
            allowed_tools: vec!["redhands_health".to_string()],
            planner_mode: PlannerMode::Deterministic,
            llm: None,
            approval_mode: ApprovalMode::Deny,
        }
    }

    pub fn with_llm(mut self, llm: LlmConfig) -> Self {
        self.planner_mode = PlannerMode::Llm;
        self.llm = Some(llm);
        self
    }

    pub fn with_approval_mode(mut self, mode: ApprovalMode) -> Self {
        self.approval_mode = mode;
        self
    }

    pub fn with_limits(mut self, max_tool_calls: usize, max_intents: usize) -> Self {
        self.max_tool_calls = max_tool_calls;
        self.max_intents = max_intents;
        self
    }

    pub fn with_allowed_tools(mut self, tools: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.allowed_tools = tools.into_iter().map(Into::into).collect();
        self
    }
}

/// Abstraction over the MCP server so the engine is unit-testable without a
/// child process.
pub trait ToolExecutor {
    fn initialize(&mut self) -> Result<String>;
    fn list_tools(&mut self) -> Result<Vec<ToolDescriptor>>;
    fn call_with_responses(
        &mut self,
        tool: &str,
        arguments: Value,
        input_responses: Option<Value>,
    ) -> Result<ToolCallResult>;

    fn call(&mut self, tool: &str, arguments: Value) -> Result<ToolCallResult> {
        self.call_with_responses(tool, arguments, None)
    }
}

pub struct McpExecutor(StdioMcpClient);

impl ToolExecutor for McpExecutor {
    fn initialize(&mut self) -> Result<String> {
        self.0.initialize()
    }

    fn list_tools(&mut self) -> Result<Vec<ToolDescriptor>> {
        Ok(self
            .0
            .tools_list()?
            .into_iter()
            .map(|tool| ToolDescriptor {
                name: tool.name,
                description: tool.description,
                input_schema: tool.input_schema,
            })
            .collect())
    }

    fn call_with_responses(
        &mut self,
        tool: &str,
        arguments: Value,
        input_responses: Option<Value>,
    ) -> Result<ToolCallResult> {
        self.0
            .tools_call_with_responses(tool, arguments, input_responses)
    }
}

/// Who answers an approval prompt. Default is deny — fail closed.
pub trait ApprovalHandler {
    fn decide(&self, tool: &str, message: &str) -> Result<(bool, String)>;
}

pub struct DenyAll;

impl ApprovalHandler for DenyAll {
    fn decide(&self, _tool: &str, _message: &str) -> Result<(bool, String)> {
        Ok((false, "operator (default deny)".to_string()))
    }
}

pub struct ApproveAll;

impl ApprovalHandler for ApproveAll {
    fn decide(&self, _tool: &str, _message: &str) -> Result<(bool, String)> {
        Ok((true, "auto-approve".to_string()))
    }
}

/// Phase 1 verifier. A later phase swaps in an LLM verifier behind this trait.
pub trait Verifier {
    fn verify(&self, intent: &Intent, output: &str) -> Verdict;
}

#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    pub value: String,
    pub reason: String,
}

pub struct HeuristicVerifier;

impl Verifier for HeuristicVerifier {
    fn verify(&self, _intent: &Intent, output: &str) -> Verdict {
        if output.contains("Status: OK") {
            Verdict {
                value: "verified".to_string(),
                reason: "tool reported Status: OK".to_string(),
            }
        } else {
            Verdict {
                value: "unverified".to_string(),
                reason: "tool output did not contain an explicit success marker".to_string(),
            }
        }
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
    Ok(McpExecutor(StdioMcpClient::spawn(
        &config.redhands_binary,
        &[],
        &env_refs,
    )?))
}

/// Run one engagement with the configured approval handler.
pub fn run(config: &Config) -> Result<EngagementView> {
    const DENY: DenyAll = DenyAll;
    const APPROVE: ApproveAll = ApproveAll;
    let handler: &dyn ApprovalHandler = match config.approval_mode {
        ApprovalMode::Deny => &DENY,
        ApprovalMode::ApproveAll => &APPROVE,
    };
    run_with(config, &HeuristicVerifier, handler)
}

pub fn run_with<V: Verifier, A: ApprovalHandler>(
    config: &Config,
    verifier: &V,
    approvals: &A,
) -> Result<EngagementView> {
    let mut executor = spawn_executor(config)?;
    run_with_executor(config, verifier, approvals, &mut executor)
}

pub fn run_with_executor<V: Verifier, A: ApprovalHandler, E: ToolExecutor>(
    config: &Config,
    verifier: &V,
    approvals: &A,
    executor: &mut E,
) -> Result<EngagementView> {
    let ledger = Ledger::open(&config.ledger_path)?;
    ledger.append(&EventBody::EngagementStarted {
        goal: config.goal.clone(),
        redhands_version: config.redhands_version.clone(),
    })?;

    let result = execute(config, &ledger, executor, verifier, approvals);
    if let Err(error) = &result {
        ledger.append(&EventBody::EngagementAborted {
            reason: error.to_string(),
        })?;
    }
    result?;
    load_view(&config.ledger_path)
}

fn make_planner(config: &Config) -> Result<Box<dyn Planner>> {
    match config.planner_mode {
        PlannerMode::Deterministic => Ok(Box::new(DeterministicPlanner)),
        PlannerMode::Llm => {
            let llm = config
                .llm
                .as_ref()
                .ok_or_else(|| anyhow!("LLM planner requested but no LLM config supplied"))?;
            let client = LlmClient::new(&llm.base_url, &llm.api_key, &llm.model);
            Ok(Box::new(LlmPlanner::new(client).with_max_intents(config.max_intents)))
        }
    }
}

fn execute<V: Verifier, A: ApprovalHandler, E: ToolExecutor>(
    config: &Config,
    ledger: &Ledger,
    executor: &mut E,
    verifier: &V,
    approvals: &A,
) -> Result<()> {
    executor.initialize().context("MCP initialize failed")?;
    let available = executor.list_tools().context("tools/list failed")?;
    let planner = make_planner(config)?;
    let intents = planner.plan(&config.goal, &available)?;
    let policy = Policy::new(config.allowed_tools.clone(), config.max_tool_calls);
    let mut findings = 0usize;
    let mut calls_made = 0usize;

    for intent in &intents {
        ledger.append(&EventBody::IntentCreated {
            id: intent.id.clone(),
            title: intent.title.clone(),
            tool: intent.tool.clone(),
            arguments: intent.arguments.clone(),
        })?;

        let decision = policy.check(&intent.tool, calls_made);
        ledger.append(&EventBody::GuardDecision {
            intent_id: intent.id.clone(),
            allowed: decision.allowed,
            reason: decision.reason.clone(),
        })?;
        if !decision.allowed {
            if decision.reason.contains("budget") {
                ledger.append(&EventBody::BudgetExhausted {
                    reason: decision.reason.clone(),
                })?;
            }
            return Err(anyhow!("guard denied '{}': {}", intent.id, decision.reason));
        }

        let mut call = executor.call(&intent.tool, intent.arguments.clone())?;
        if call.result_type.as_deref() == Some("input_required") {
            let request_id = call
                .input_requests
                .as_ref()
                .and_then(|value| value.pointer("/approval/requestId"))
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            let message = call
                .input_requests
                .as_ref()
                .and_then(|value| value.pointer("/approval/message"))
                .and_then(Value::as_str)
                .unwrap_or("operator approval required")
                .to_string();
            ledger.append(&EventBody::ApprovalRequested {
                intent_id: intent.id.clone(),
                tool: intent.tool.clone(),
                request_id,
            })?;
            let (approved, decided_by) = approvals.decide(&intent.tool, &message)?;
            ledger.append(&EventBody::ApprovalDecisionRecorded {
                intent_id: intent.id.clone(),
                approved,
                decided_by,
            })?;
            if !approved {
                return Err(anyhow!("approval denied for '{}'", intent.id));
            }
            call = executor.call_with_responses(
                &intent.tool,
                intent.arguments.clone(),
                Some(serde_json::json!({"approval": {"approved": true}})),
            )?;
        }

        let call_event = ledger.append(&EventBody::ToolCallCompleted {
            intent_id: intent.id.clone(),
            tool: intent.tool.clone(),
            content: call.content.clone(),
            is_error: call.is_error,
        })?;
        if call.is_error {
            return Err(anyhow!("tool '{}' reported an error", intent.tool));
        }
        calls_made += 1;

        let finding_id = format!("finding-{}", findings + 1);
        ledger.append(&EventBody::FindingRecorded {
            id: finding_id.clone(),
            title: format!("{} ({})", intent.title, call_event.seq),
            severity: "info".to_string(),
            evidence_seq: call_event.seq,
        })?;
        let verdict = verifier.verify(intent, &call.content);
        ledger.append(&EventBody::FindingVerified {
            finding_id,
            verdict: verdict.value,
            evidence_seq: call_event.seq,
        })?;
        findings += 1;
    }

    ledger.append(&EventBody::EngagementCompleted { findings })?;
    Ok(())
}

pub fn load_view(ledger_path: &Path) -> Result<EngagementView> {
    let ledger = Ledger::open(ledger_path)?;
    ledger.verify_chain().context("ledger integrity check failed")?;
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
        gate: bool,
    }

    impl ToolExecutor for MockExecutor {
        fn initialize(&mut self) -> Result<String> {
            Ok("2026-07-28".to_string())
        }
        fn list_tools(&mut self) -> Result<Vec<ToolDescriptor>> {
            Ok(vec![ToolDescriptor {
                name: "redhands_health".to_string(),
                description: "health".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
            }])
        }
        fn call_with_responses(
            &mut self,
            tool: &str,
            _arguments: Value,
            input_responses: Option<Value>,
        ) -> Result<ToolCallResult> {
            self.calls.push(tool.to_string());
            if self.gate && input_responses.is_none() {
                return Ok(ToolCallResult {
                    content: "requires operator approval".to_string(),
                    is_error: false,
                    result_type: Some("input_required".to_string()),
                    input_requests: Some(serde_json::json!({
                        "approval": {
                            "type": "elicitation/create",
                            "message": "approve this tool?",
                            "requestId": "req_test"
                        }
                    })),
                });
            }
            Ok(ToolCallResult {
                content: "### Status: OK".to_string(),
                is_error: false,
                result_type: None,
                input_requests: None,
            })
        }
    }

    #[test]
    fn full_loop_with_mock() {
        let dir = tempdir().unwrap();
        let config = Config::new(
            "health check",
            PathBuf::from("unused"),
            dir.path().join("engagement.db"),
        );
        let mut executor = MockExecutor {
            calls: Vec::new(),
            gate: false,
        };
        let view = run_with_executor(&config, &HeuristicVerifier, &DenyAll, &mut executor).unwrap();
        assert!(view.completed);
        assert_eq!(view.findings.len(), 1);
        assert_eq!(view.verifications[0].verdict, "verified");
        assert_eq!(executor.calls, vec!["redhands_health"]);
        assert!(report_markdown(&config.ledger_path)
            .unwrap()
            .contains("Status: OK"));
    }

    #[test]
    fn approval_round_trip_is_recorded() {
        let dir = tempdir().unwrap();
        let config = Config::new(
            "health check",
            PathBuf::from("unused"),
            dir.path().join("approval.db"),
        );
        let mut executor = MockExecutor {
            calls: Vec::new(),
            gate: true,
        };
        let view =
            run_with_executor(&config, &HeuristicVerifier, &ApproveAll, &mut executor).unwrap();
        assert!(view.completed);
        assert_eq!(view.approvals.len(), 1);
        assert_eq!(view.approvals[0].approved, Some(true));
        assert_eq!(view.approvals[0].decided_by, "auto-approve");
        assert_eq!(executor.calls.len(), 2);
    }

    #[test]
    fn denied_approval_aborts() {
        let dir = tempdir().unwrap();
        let config = Config::new(
            "health check",
            PathBuf::from("unused"),
            dir.path().join("deny.db"),
        );
        let mut executor = MockExecutor {
            calls: Vec::new(),
            gate: true,
        };
        assert!(run_with_executor(&config, &HeuristicVerifier, &DenyAll, &mut executor).is_err());
        assert_eq!(executor.calls.len(), 1);
        let view = load_view(&config.ledger_path).unwrap();
        assert!(view.abort_reason.unwrap().contains("approval denied"));
    }
}

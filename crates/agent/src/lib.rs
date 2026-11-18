//! Planner interface, the Phase 0 deterministic planner and the Phase 1
//! LLM planner. A planner emits typed intents; the engine never parses prose.

use anyhow::{anyhow, Context, Result};
use redagent_llm::{extract_json_object, LlmClient};
use serde::Deserialize;
use serde_json::Value;

pub const HEALTH_TOOL: &str = "redhands_health";

/// The subset of a RedHands tool definition the planner needs to decide.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolDescriptor {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Intent {
    pub id: String,
    pub title: String,
    pub tool: String,
    pub arguments: Value,
    pub rationale: String,
}

pub trait Planner {
    fn plan(&self, goal: &str, available_tools: &[ToolDescriptor]) -> Result<Vec<Intent>>;
}

/// Minimal abstraction over an LLM so the planner is unit-testable without
/// network access. `LlmClient` implements it.
pub trait JsonCompleter {
    fn complete_json(&self, system: &str, user: &str) -> Result<String>;
}

impl JsonCompleter for LlmClient {
    fn complete_json(&self, system: &str, user: &str) -> Result<String> {
        LlmClient::complete_json(self, system, user)
    }
}

/// Phase 0 planner: no LLM, no network. Produces one health probe intent,
/// which exercises the complete loop (ledger → guard → MCP → report).
#[derive(Debug, Default)]
pub struct DeterministicPlanner;

impl Planner for DeterministicPlanner {
    fn plan(&self, goal: &str, available_tools: &[ToolDescriptor]) -> Result<Vec<Intent>> {
        if goal.trim().is_empty() {
            return Err(anyhow!("goal must not be empty"));
        }
        if !available_tools.iter().any(|tool| tool.name == HEALTH_TOOL) {
            return Err(anyhow!("{HEALTH_TOOL} is not available on this RedHands server"));
        }
        Ok(vec![Intent {
            id: "intent-1".to_string(),
            title: "Verify RedHands health".to_string(),
            tool: HEALTH_TOOL.to_string(),
            arguments: serde_json::json!({}),
            rationale: "deterministic Phase 0 probe".to_string(),
        }])
    }
}

#[derive(Debug, Deserialize)]
struct PlanPayload {
    intents: Vec<PlannedIntent>,
}

#[derive(Debug, Deserialize)]
struct PlannedIntent {
    title: String,
    tool: String,
    #[serde(default)]
    arguments: Value,
    #[serde(default)]
    rationale: String,
}

/// Phase 1 planner: asks an OpenAI-compatible LLM for a JSON plan, validates
/// every intent against the live RedHands tool catalog, and retries once on
/// malformed output. No tool name is ever taken on trust.
pub struct LlmPlanner<C: JsonCompleter> {
    completer: C,
    max_intents: usize,
}

impl<C: JsonCompleter> LlmPlanner<C> {
    pub fn new(completer: C) -> Self {
        Self {
            completer,
            max_intents: 6,
        }
    }

    pub fn with_max_intents(mut self, max_intents: usize) -> Self {
        self.max_intents = max_intents.max(1);
        self
    }

    fn system_prompt(&self, retry: Option<&str>) -> String {
        let mut prompt = format!(
            "You are the planner of RedAgent, an autonomous offensive-security agent for \
             explicitly authorized engagements. Return ONLY a JSON object with this shape:\n\
             {{\"intents\":[{{\"title\":\"short label\",\"tool\":\"exact_tool_name\",\
             \"arguments\":{{}},\"rationale\":\"why this step\"}}]}}\n\n\
             Rules: choose tool names only from the supplied catalog; never invent a tool; \
             keep the plan minimal (at most {} intents); arguments must be a JSON object \
             matching that tool's inputSchema; no prose outside JSON.",
            self.max_intents
        );
        if let Some(error) = retry {
            prompt.push_str(&format!(
                "\n\nYour previous response was rejected: {error}. Return corrected JSON only."
            ));
        }
        prompt
    }

    fn parse_and_validate(
        &self,
        text: &str,
        available_tools: &[ToolDescriptor],
    ) -> Result<Vec<Intent>> {
        let value = extract_json_object(text).context("planner output is not a JSON object")?;
        let payload: PlanPayload =
            serde_json::from_value(value).context("planner output has an invalid plan shape")?;
        if payload.intents.is_empty() {
            return Err(anyhow!("planner produced no intents"));
        }
        if payload.intents.len() > self.max_intents {
            return Err(anyhow!(
                "planner produced {} intents, limit is {}",
                payload.intents.len(),
                self.max_intents
            ));
        }
        let mut intents = Vec::with_capacity(payload.intents.len());
        for (index, intent) in payload.intents.into_iter().enumerate() {
            let title = intent.title.trim();
            if title.is_empty() {
                return Err(anyhow!("intent {} has an empty title", index + 1));
            }
            if !available_tools.iter().any(|tool| tool.name == intent.tool) {
                return Err(anyhow!(
                    "intent {} uses unknown tool '{}'",
                    index + 1,
                    intent.tool
                ));
            }
            let arguments = match intent.arguments {
                Value::Null => serde_json::json!({}),
                Value::Object(map) => Value::Object(map),
                _ => return Err(anyhow!("intent {} arguments must be a JSON object", index + 1)),
            };
            intents.push(Intent {
                id: format!("intent-{}", index + 1),
                title: title.to_string(),
                tool: intent.tool,
                arguments,
                rationale: intent.rationale,
            });
        }
        Ok(intents)
    }
}

impl<C: JsonCompleter> Planner for LlmPlanner<C> {
    fn plan(&self, goal: &str, available_tools: &[ToolDescriptor]) -> Result<Vec<Intent>> {
        if goal.trim().is_empty() {
            return Err(anyhow!("goal must not be empty"));
        }
        let catalog = serde_json::json!({
            "tools": available_tools
                .iter()
                .map(|tool| serde_json::json!({
                    "name": tool.name,
                    "description": tool.description,
                    "inputSchema": tool.input_schema,
                }))
                .collect::<Vec<_>>(),
        })
        .to_string();
        let user = format!(
            "Authorized engagement goal: {goal}\n\nRedHands tool catalog:\n{catalog}\n\nReturn the JSON plan now."
        );

        match self.completer.complete_json(&self.system_prompt(None), &user) {
            Ok(text) => match self.parse_and_validate(&text, available_tools) {
                Ok(intents) => return Ok(intents),
                Err(error) => {
                    let retry_error = error.to_string();
                    let retry = self
                        .completer
                        .complete_json(&self.system_prompt(Some(&retry_error)), &user)
                        .context("LLM retry failed")?;
                    return self
                        .parse_and_validate(&retry, available_tools)
                        .context("LLM plan invalid after one retry");
                }
            },
            Err(error) => return Err(error).context("LLM planning request failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn tools() -> Vec<ToolDescriptor> {
        vec![
            ToolDescriptor {
                name: HEALTH_TOOL.to_string(),
                description: "health check".to_string(),
                input_schema: serde_json::json!({"type": "object", "properties": {}}),
            },
            ToolDescriptor {
                name: "nmap_port_scan".to_string(),
                description: "port scan".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
            },
        ]
    }

    struct Stub {
        replies: Vec<String>,
        calls: Cell<usize>,
    }

    impl JsonCompleter for Stub {
        fn complete_json(&self, _system: &str, _user: &str) -> Result<String> {
            let index = self.calls.get();
            self.calls.set(index + 1);
            self.replies
                .get(index)
                .cloned()
                .ok_or_else(|| anyhow!("no more stub replies"))
        }
    }

    #[test]
    fn deterministic_planner_still_works() {
        let intents = DeterministicPlanner.plan("check", &tools()).unwrap();
        assert_eq!(intents.len(), 1);
        assert_eq!(intents[0].tool, HEALTH_TOOL);
    }

    #[test]
    fn llm_planner_accepts_fenced_json() {
        let reply = "```json\n{\"intents\":[{\"title\":\"probe\",\"tool\":\"redhands_health\",\"arguments\":{},\"rationale\":\"baseline\"}]}\n```";
        let planner = LlmPlanner::new(Stub {
            replies: vec![reply.to_string()],
            calls: Cell::new(0),
        });
        let intents = planner.plan("goal", &tools()).unwrap();
        assert_eq!(intents.len(), 1);
        assert_eq!(intents[0].id, "intent-1");
        assert_eq!(intents[0].rationale, "baseline");
    }

    #[test]
    fn llm_planner_rejects_unknown_tool() {
        let reply = r#"{"intents":[{"title":"bad","tool":"invented_tool","arguments":{}}]}"#;
        let planner = LlmPlanner::new(Stub {
            replies: vec![reply.to_string(), reply.to_string()],
            calls: Cell::new(0),
        });
        assert!(planner.plan("goal", &tools()).is_err());
        assert_eq!(planner.completer.calls.get(), 2);
    }

    #[test]
    fn llm_planner_retries_once_then_succeeds() {
        let bad = "not json at all";
        let good = r#"{"intents":[{"title":"ok","tool":"redhands_health"}]}"#;
        let planner = LlmPlanner::new(Stub {
            replies: vec![bad.to_string(), good.to_string()],
            calls: Cell::new(0),
        });
        let intents = planner.plan("goal", &tools()).unwrap();
        assert_eq!(intents[0].arguments, serde_json::json!({}));
        assert_eq!(planner.completer.calls.get(), 2);
    }
}

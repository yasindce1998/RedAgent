//! Planner interface and the Phase 0 deterministic planner.
//! A future LLM planner implements the same `Planner` trait, so the engine
//! and ledger do not change when real reasoning is introduced.

use anyhow::{anyhow, Result};

pub const HEALTH_TOOL: &str = "redhands_health";

#[derive(Debug, Clone, PartialEq)]
pub struct Intent {
    pub id: String,
    pub title: String,
    pub tool: String,
    pub arguments: serde_json::Value,
}

pub trait Planner {
    fn plan(&self, goal: &str, available_tools: &[String]) -> Result<Vec<Intent>>;
}

/// Phase 0 planner: no LLM, no network. Produces one health probe intent,
/// which exercises the complete loop (ledger → guard → MCP → report).
#[derive(Debug, Default)]
pub struct DeterministicPlanner;

impl Planner for DeterministicPlanner {
    fn plan(&self, goal: &str, available_tools: &[String]) -> Result<Vec<Intent>> {
        if goal.trim().is_empty() {
            return Err(anyhow!("goal must not be empty"));
        }
        if !available_tools.iter().any(|tool| tool == HEALTH_TOOL) {
            return Err(anyhow!(
                "{HEALTH_TOOL} is not available on this RedHands server"
            ));
        }
        Ok(vec![Intent {
            id: "intent-1".to_string(),
            title: "Verify RedHands health".to_string(),
            tool: HEALTH_TOOL.to_string(),
            arguments: serde_json::json!({}),
        }])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans_a_health_intent() {
        let planner = DeterministicPlanner;
        let intents = planner
            .plan("check the lab", &[HEALTH_TOOL.to_string()])
            .unwrap();
        assert_eq!(intents.len(), 1);
        assert_eq!(intents[0].tool, HEALTH_TOOL);
    }

    #[test]
    fn rejects_empty_goal_and_missing_tool() {
        let planner = DeterministicPlanner;
        assert!(planner.plan("", &[HEALTH_TOOL.to_string()]).is_err());
        assert!(planner.plan("x", &[]).is_err());
    }
}

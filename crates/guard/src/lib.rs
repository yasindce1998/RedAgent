//! Phase 0 guard: a tool allowlist and a hard cap on tool calls.
//! Scope matching, approval elicitation and prompt-injection framing arrive
//! in Phase 1; this crate is intentionally tiny and exhaustively tested.

use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct Decision {
    pub allowed: bool,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct Policy {
    allowed_tools: HashSet<String>,
    max_tool_calls: usize,
}

impl Policy {
    pub fn new(
        allowed_tools: impl IntoIterator<Item = impl Into<String>>,
        max_tool_calls: usize,
    ) -> Self {
        Self {
            allowed_tools: allowed_tools.into_iter().map(Into::into).collect(),
            max_tool_calls,
        }
    }

    pub fn check(&self, tool: &str, calls_already_made: usize) -> Decision {
        if calls_already_made >= self.max_tool_calls {
            return Decision {
                allowed: false,
                reason: format!(
                    "tool-call budget exhausted ({calls_already_made}/{})",
                    self.max_tool_calls
                ),
            };
        }
        if !self.allowed_tools.contains(tool) {
            return Decision {
                allowed: false,
                reason: format!("tool '{tool}' is not in the allowlist"),
            };
        }
        Decision {
            allowed: true,
            reason: "tool is allowlisted and budget remains".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlisted_tool_passes_with_budget() {
        let policy = Policy::new(["redhands_health"], 2);
        assert!(policy.check("redhands_health", 0).allowed);
        assert!(policy.check("redhands_health", 1).allowed);
    }

    #[test]
    fn deny_unknown_tool_and_exhausted_budget() {
        let policy = Policy::new(["redhands_health"], 1);
        let denied = policy.check("msf_module_run", 0);
        assert!(!denied.allowed);
        assert!(denied.reason.contains("allowlist"));
        let exhausted = policy.check("redhands_health", 1);
        assert!(!exhausted.allowed);
        assert!(exhausted.reason.contains("budget"));
    }
}

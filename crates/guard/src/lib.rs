//! Guard primitives for RedAgent.
//!
//! [`Policy::check`] remains the original Phase 0 helper: a tool allowlist
//! plus a hard cap on tool calls. [`evaluate_call`] is the Phase 1 composition
//! helper; it layers scope and policy-rule decisions on top of the same policy
//! without changing the behaviour of [`Policy::check`].

use std::collections::HashSet;

use redagent_scope::{evaluate_rules, RuleEffect};

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

/// Everything the guard needs to know about a single tool call.
#[derive(Clone, Debug)]
pub struct CallContext<'a> {
    pub tool: &'a str,
    pub args: &'a serde_json::Value,
    pub read_only: bool,
    pub in_scope: bool,
    pub calls_made: usize,
}

/// The composed decision for a tool call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuardEffect {
    Allow,
    Deny,
    RequireApproval,
    AutoApprove { rule_id: String },
}

/// A [`GuardEffect`] together with a human-readable explanation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardVerdict {
    pub effect: GuardEffect,
    pub reason: String,
}

/// Compose the allowlist, call budget, scope decision and policy rules for one
/// call. Precedence, highest first:
///
/// 1. an explicit `Deny` rule,
/// 2. an allowlist miss,
/// 3. an exhausted call budget,
/// 4. a target that is out of scope (including unresolvable targets, which
///    callers report as `in_scope: false`),
/// 5. an `AutoApprove` rule,
/// 6. a `RequireApproval` rule,
/// 7. plain `Allow`.
///
/// Note that deny rules outrank an allowlist miss or budget exhaustion even
/// when they appear later in the rule list, whereas `AutoApprove` and
/// `RequireApproval` follow normal first-match-wins ordering among themselves
/// (auto-approve wins if it appears first).
pub fn evaluate_call(
    policy: &Policy,
    rules: &[redagent_scope::PolicyRule],
    ctx: &CallContext<'_>,
) -> GuardVerdict {
    // A deny rule is absolute: it must be detected even when an earlier rule
    // would otherwise match, so each effect gets its own first-match pass.
    if let Some((_, rule_id)) = first_rule_with_effect(rules, ctx, RuleEffect::Deny) {
        return GuardVerdict {
            effect: GuardEffect::Deny,
            reason: format!("denied by rule '{rule_id}'"),
        };
    }

    if !policy.allowed_tools.contains(ctx.tool) {
        return GuardVerdict {
            effect: GuardEffect::Deny,
            reason: format!("tool '{}' is not in the allowlist", ctx.tool),
        };
    }

    if ctx.calls_made >= policy.max_tool_calls {
        return GuardVerdict {
            effect: GuardEffect::Deny,
            reason: format!(
                "tool-call budget exhausted ({}/{})",
                ctx.calls_made, policy.max_tool_calls
            ),
        };
    }

    if !ctx.in_scope {
        return GuardVerdict {
            effect: GuardEffect::Deny,
            reason: "target is out of scope or unresolvable".to_string(),
        };
    }

    if let Some((_, rule_id)) = first_rule_with_effect(rules, ctx, RuleEffect::AutoApprove) {
        return GuardVerdict {
            effect: GuardEffect::AutoApprove { rule_id },
            reason: "auto-approved by policy rule".to_string(),
        };
    }

    if let Some((_, rule_id)) = first_rule_with_effect(rules, ctx, RuleEffect::RequireApproval) {
        return GuardVerdict {
            effect: GuardEffect::RequireApproval,
            reason: format!("approval required by rule '{rule_id}'"),
        };
    }

    GuardVerdict {
        effect: GuardEffect::Allow,
        reason: format!(
            "tool '{}' is allowlisted, within budget and in scope",
            ctx.tool
        ),
    }
}

fn first_rule_with_effect(
    rules: &[redagent_scope::PolicyRule],
    ctx: &CallContext<'_>,
    effect: RuleEffect,
) -> Option<(RuleEffect, String)> {
    let subset: Vec<redagent_scope::PolicyRule> = rules
        .iter()
        .filter(|rule| rule.effect == effect)
        .cloned()
        .collect();
    evaluate_rules(&subset, ctx.tool, ctx.read_only, ctx.in_scope)
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

    fn context(tool: &str, in_scope: bool, calls_made: usize) -> CallContext<'static> {
        // A leaked static value keeps CallContext simple in tests.
        let args: &'static serde_json::Value = Box::leak(Box::new(serde_json::json!({
            "target": "example.com",
        })));
        CallContext {
            tool: Box::leak(tool.to_string().into_boxed_str()),
            args,
            read_only: false,
            in_scope,
            calls_made,
        }
    }

    fn parse_rules(json: serde_json::Value) -> Vec<redagent_scope::PolicyRule> {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn evaluate_call_defaults_to_allow_when_everything_is_fine() {
        let policy = Policy::new(["redhands_health"], 3);
        let verdict = evaluate_call(&policy, &[], &context("redhands_health", true, 2));
        assert_eq!(verdict.effect, GuardEffect::Allow);
        assert!(verdict.reason.contains("in scope"));
    }

    #[test]
    fn evaluate_call_enforces_allowlist_budget_and_scope() {
        let policy = Policy::new(["redhands_health"], 1);

        let miss = evaluate_call(&policy, &[], &context("unknown_tool", true, 0));
        assert_eq!(miss.effect, GuardEffect::Deny);
        assert!(miss.reason.contains("allowlist"));

        let budget = evaluate_call(&policy, &[], &context("redhands_health", true, 1));
        assert_eq!(budget.effect, GuardEffect::Deny);
        assert!(budget.reason.contains("budget"));

        let scope = evaluate_call(&policy, &[], &context("redhands_health", false, 0));
        assert_eq!(scope.effect, GuardEffect::Deny);
        assert!(scope.reason.contains("scope"));
    }

    #[test]
    fn deny_rule_outranks_everything_even_when_listed_last() {
        let policy = Policy::new(["redhands_health"], 1);
        let rules = parse_rules(serde_json::json!([
            { "id": "auto", "tool_pattern": "redhands_*", "effect": "AutoApprove" },
            { "id": "hard-deny", "tool_pattern": "REDHANDS_*", "effect": "Deny" }
        ]));

        // Deny beats a matching auto-approve rule.
        let verdict = evaluate_call(&policy, &rules, &context("redhands_health", true, 0));
        assert_eq!(
            verdict.effect,
            GuardEffect::Deny,
            "deny rule must win regardless of order"
        );
        assert!(verdict.reason.contains("hard-deny"));

        // A non-matching deny rule leaves the normal allowlist check in place.
        let miss = evaluate_call(&policy, &rules, &context("other_tool", true, 0));
        assert_eq!(miss.effect, GuardEffect::Deny);
        assert!(miss.reason.contains("allowlist"));

        // A matching predicate makes the deny rule win over budget exhaustion.
        let mut ctx = context("redhands_health", true, 5);
        ctx.read_only = true;
        let scoped_rules = parse_rules(serde_json::json!([
            { "id": "ro-deny", "tool_pattern": "*", "read_only": true, "effect": "Deny" }
        ]));
        let scoped = evaluate_call(&policy, &scoped_rules, &ctx);
        assert_eq!(scoped.effect, GuardEffect::Deny);
        assert!(scoped.reason.contains("ro-deny"));
    }

    #[test]
    fn auto_approve_and_require_approval_respect_predicates_and_first_match() {
        let policy = Policy::new(["redhands_health"], 3);
        let rules = parse_rules(serde_json::json!([
            {
                "id": "wrong-predicate",
                "tool_pattern": "*",
                "read_only": true,
                "effect": "AutoApprove"
            },
            {
                "id": "require",
                "tool_pattern": "redhands_*",
                "in_scope": true,
                "effect": "RequireApproval"
            },
            {
                "id": "auto",
                "tool_pattern": "REDHANDS_*",
                "effect": "AutoApprove"
            }
        ]));

        // The read_only predicate rules out the first auto-approve rule;
        // without any other auto-approve rule, approval is required.
        let without_auto = &rules[..2];
        let require = evaluate_call(&policy, without_auto, &context("redhands_health", true, 0));
        assert_eq!(require.effect, GuardEffect::RequireApproval);
        assert!(require.reason.contains("require"));

        // Auto-approve outranks require-approval even when listed later.
        let auto_wins = evaluate_call(&policy, &rules, &context("redhands_health", true, 0));
        assert_eq!(
            auto_wins.effect,
            GuardEffect::AutoApprove {
                rule_id: "auto".into()
            }
        );

        let auto_rules = parse_rules(serde_json::json!([
            {
                "id": "ro-auto",
                "tool_pattern": "*",
                "read_only": true,
                "effect": "AutoApprove"
            },
            { "id": "require", "tool_pattern": "*", "effect": "RequireApproval" }
        ]));
        let mut ctx = context("redhands_health", true, 0);
        ctx.read_only = true;
        let auto = evaluate_call(&policy, &auto_rules, &ctx);
        assert_eq!(
            auto.effect,
            GuardEffect::AutoApprove {
                rule_id: "ro-auto".into()
            }
        );
    }

    #[test]
    fn extracted_targets_and_scope_decision_feed_the_guard() {
        use redagent_scope::{extract_targets, Scope, ScopeDecision};

        fn in_scope(scope: &Scope, args: &serde_json::Value) -> bool {
            let paths = ["target".to_string(), "hosts".to_string()];
            let targets = extract_targets(args, &paths);
            !targets.is_empty()
                && targets
                    .iter()
                    .all(|target| matches!(scope.allows_target(target), ScopeDecision::InScope))
        }

        let scope = Scope::new(vec!["10.0.0.0/8".into()], vec![], vec![]).unwrap();
        let policy = Policy::new(["redhands_scan"], 2);

        let good = serde_json::json!({ "target": "10.0.0.5", "hosts": ["10.1.2.3"] });
        let ctx = CallContext {
            tool: "redhands_scan",
            args: &good,
            read_only: false,
            in_scope: in_scope(&scope, &good),
            calls_made: 0,
        };
        assert_eq!(evaluate_call(&policy, &[], &ctx).effect, GuardEffect::Allow);

        let bad = serde_json::json!({ "target": "10.0.0.5", "hosts": ["192.168.1.1"] });
        let ctx = CallContext {
            tool: "redhands_scan",
            args: &bad,
            read_only: false,
            in_scope: in_scope(&scope, &bad),
            calls_made: 0,
        };
        assert_eq!(evaluate_call(&policy, &[], &ctx).effect, GuardEffect::Deny);
    }
}

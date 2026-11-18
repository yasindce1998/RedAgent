use serde::{Deserialize, Serialize};
use crate::events::{EventBody, StoredEvent};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentView {
    pub id: String,
    pub title: String,
    pub tool: String,
    pub allowed: Option<bool>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallView {
    pub intent_id: String,
    pub tool: String,
    pub content: String,
    pub is_error: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingView {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub evidence_seq: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalView {
    pub intent_id: String,
    pub tool: String,
    pub request_id: String,
    pub approved: Option<bool>,
    pub decided_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationView {
    pub finding_id: String,
    pub verdict: String,
    pub evidence_seq: i64,
}

/// Read-only view over the ledger. Rebuilt from events on demand.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct EngagementView {
    pub goal: Option<String>,
    pub redhands_version: Option<String>,
    pub intents: Vec<IntentView>,
    pub tool_calls: Vec<ToolCallView>,
    pub findings: Vec<FindingView>,
    pub approvals: Vec<ApprovalView>,
    pub verifications: Vec<VerificationView>,
    pub budget_exhausted: Option<String>,
    pub completed: bool,
    pub abort_reason: Option<String>,
}

pub fn project(events: &[StoredEvent]) -> EngagementView {
    let mut view = EngagementView::default();
    for event in events {
        match &event.body {
            EventBody::EngagementStarted {
                goal,
                redhands_version,
            } => {
                view.goal = Some(goal.clone());
                view.redhands_version = Some(redhands_version.clone());
            }
            EventBody::IntentCreated {
                id, title, tool, ..
            } => {
                view.intents.push(IntentView {
                    id: id.clone(),
                    title: title.clone(),
                    tool: tool.clone(),
                    allowed: None,
                    reason: String::new(),
                });
            }
            EventBody::GuardDecision {
                intent_id,
                allowed,
                reason,
            } => {
                if let Some(intent) = view.intents.iter_mut().find(|i| &i.id == intent_id) {
                    intent.allowed = Some(*allowed);
                    intent.reason = reason.clone();
                }
            }
            EventBody::ToolCallCompleted {
                intent_id,
                tool,
                content,
                is_error,
            } => {
                view.tool_calls.push(ToolCallView {
                    intent_id: intent_id.clone(),
                    tool: tool.clone(),
                    content: content.clone(),
                    is_error: *is_error,
                });
            }
            EventBody::FindingRecorded {
                id,
                title,
                severity,
                evidence_seq,
            } => {
                view.findings.push(FindingView {
                    id: id.clone(),
                    title: title.clone(),
                    severity: severity.clone(),
                    evidence_seq: *evidence_seq,
                });
            }
            EventBody::ApprovalRequested {
                intent_id,
                tool,
                request_id,
            } => {
                view.approvals.push(ApprovalView {
                    intent_id: intent_id.clone(),
                    tool: tool.clone(),
                    request_id: request_id.clone(),
                    approved: None,
                    decided_by: String::new(),
                });
            }
            EventBody::ApprovalDecisionRecorded {
                intent_id,
                approved,
                decided_by,
            } => {
                if let Some(approval) = view
                    .approvals
                    .iter_mut()
                    .find(|a| &a.intent_id == intent_id)
                {
                    approval.approved = Some(*approved);
                    approval.decided_by = decided_by.clone();
                }
            }
            EventBody::FindingVerified {
                finding_id,
                verdict,
                evidence_seq,
            } => {
                view.verifications.push(VerificationView {
                    finding_id: finding_id.clone(),
                    verdict: verdict.clone(),
                    evidence_seq: *evidence_seq,
                });
            }
            EventBody::BudgetExhausted { reason } => {
                view.budget_exhausted = Some(reason.clone());
            }
            EventBody::EngagementCompleted { .. } => view.completed = true,
            EventBody::EngagementAborted { reason } => view.abort_reason = Some(reason.clone()),
        }
    }
    view
}

pub fn render_markdown(view: &EngagementView) -> String {
    let mut out = String::new();
    out.push_str("# RedAgent engagement report\n\n");
    out.push_str(&format!(
        "- **Goal:** {}\n- **RedHands:** {}\n- **Status:** {}\n",
        view.goal.as_deref().unwrap_or("(none)"),
        view.redhands_version.as_deref().unwrap_or("(unknown)"),
        if view.completed {
            "completed".to_string()
        } else if let Some(reason) = &view.abort_reason {
            format!("aborted — {reason}")
        } else {
            "in progress".to_string()
        }
    ));
    if let Some(reason) = &view.budget_exhausted {
        out.push_str(&format!("- **Budget exhausted:** {reason}\n"));
    }
    out.push('\n');

    out.push_str("## Intents\n\n");
    if view.intents.is_empty() {
        out.push_str("_none_\n\n");
    } else {
        out.push_str("| Intent | Tool | Allowed |\n|---|---|---|\n");
        for intent in &view.intents {
            out.push_str(&format!(
                "| {} | {} | {} |\n",
                intent.title,
                intent.tool,
                match intent.allowed {
                    Some(true) => "yes",
                    Some(false) => "no",
                    None => "not evaluated",
                }
            ));
        }
        out.push('\n');
    }

    out.push_str("## Findings\n\n");
    if view.findings.is_empty() {
        out.push_str("_none_\n\n");
    } else {
        for finding in &view.findings {
            out.push_str(&format!(
                "### {} ({})\n\nEvidence: ledger event #{}\n\n",
                finding.title, finding.severity, finding.evidence_seq
            ));
        }
    }

    out.push_str("## Tool evidence\n\n");
    for call in &view.tool_calls {
        out.push_str(&format!(
            "### `{}` (intent {}{})\n\n```text\n{}\n```\n\n",
            call.tool,
            call.intent_id,
            if call.is_error { ", error" } else { "" },
            call.content
        ));
    }

    if !view.approvals.is_empty() {
        out.push_str("## Approvals\n\n");
        out.push_str("| Intent | Tool | Approved | Decided by |\n|---|---|---|---|\n");
        for approval in &view.approvals {
            out.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                approval.intent_id,
                approval.tool,
                match approval.approved {
                    Some(true) => "yes",
                    Some(false) => "no",
                    None => "pending",
                },
                if approval.decided_by.is_empty() {
                    "(pending)"
                } else {
                    approval.decided_by.as_str()
                }
            ));
        }
        out.push('\n');
    }

    if !view.verifications.is_empty() {
        out.push_str("## Verification\n\n");
        for verification in &view.verifications {
            out.push_str(&format!(
                "- **{}** → {} → ledger event #{}\n",
                verification.finding_id, verification.verdict, verification.evidence_seq
            ));
        }
        out.push('\n');
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(body: EventBody) -> StoredEvent {
        StoredEvent {
            seq: 1,
            ts: "2026-01-01T00:00:00Z".into(),
            body,
            prev_hash: "0".repeat(64),
            hash: "1".repeat(64),
        }
    }

    #[test]
    fn project_full_engagement() {
        let events = vec![
            event(EventBody::EngagementStarted {
                goal: "g".into(),
                redhands_version: "v0.6.3".into(),
            }),
            event(EventBody::IntentCreated {
                id: "i1".into(),
                title: "probe".into(),
                tool: "redhands_health".into(),
                arguments: serde_json::json!({}),
            }),
            event(EventBody::GuardDecision {
                intent_id: "i1".into(),
                allowed: true,
                reason: "allowlisted".into(),
            }),
            event(EventBody::ToolCallCompleted {
                intent_id: "i1".into(),
                tool: "redhands_health".into(),
                content: "### Status: OK".into(),
                is_error: false,
            }),
            event(EventBody::FindingRecorded {
                id: "f1".into(),
                title: "Health OK".into(),
                severity: "info".into(),
                evidence_seq: 4,
            }),
            event(EventBody::EngagementCompleted { findings: 1 }),
        ];
        let view = project(&events);
        assert_eq!(view.goal.as_deref(), Some("g"));
        assert_eq!(view.intents.len(), 1);
        assert_eq!(view.intents[0].allowed, Some(true));
        assert_eq!(view.findings.len(), 1);
        assert!(view.completed);
        let md = render_markdown(&view);
        assert!(md.contains("Health OK"));
        assert!(md.contains("redhands_health"));
        assert!(md.contains("completed"));
    }

    #[test]
    fn project_approval_verification_and_budget_events() {
        let events = vec![
            event(EventBody::ApprovalRequested {
                intent_id: "i1".into(),
                tool: "redhands_scan".into(),
                request_id: "req-1".into(),
            }),
            event(EventBody::ApprovalRequested {
                intent_id: "i2".into(),
                tool: "redhands_exec".into(),
                request_id: "req-2".into(),
            }),
            event(EventBody::ApprovalDecisionRecorded {
                intent_id: "i1".into(),
                approved: true,
                decided_by: "operator".into(),
            }),
            event(EventBody::ApprovalDecisionRecorded {
                intent_id: "missing".into(),
                approved: false,
                decided_by: "ghost".into(),
            }),
            event(EventBody::FindingVerified {
                finding_id: "f1".into(),
                verdict: "confirmed".into(),
                evidence_seq: 7,
            }),
            event(EventBody::FindingVerified {
                finding_id: "f2".into(),
                verdict: "rejected".into(),
                evidence_seq: 9,
            }),
            event(EventBody::BudgetExhausted {
                reason: "token limit".into(),
            }),
        ];
        let view = project(&events);

        assert_eq!(view.approvals.len(), 2);
        assert_eq!(view.approvals[0].intent_id, "i1");
        assert_eq!(view.approvals[0].tool, "redhands_scan");
        assert_eq!(view.approvals[0].request_id, "req-1");
        assert_eq!(view.approvals[0].approved, Some(true));
        assert_eq!(view.approvals[0].decided_by, "operator");
        // The decision for an unknown intent must not create an approval.
        assert_eq!(view.approvals[1].intent_id, "i2");
        assert_eq!(view.approvals[1].approved, None);
        assert_eq!(view.approvals[1].decided_by, "");

        assert_eq!(view.verifications.len(), 2);
        assert_eq!(view.verifications[0].finding_id, "f1");
        assert_eq!(view.verifications[0].verdict, "confirmed");
        assert_eq!(view.verifications[0].evidence_seq, 7);
        assert_eq!(view.verifications[1].finding_id, "f2");
        assert_eq!(view.verifications[1].evidence_seq, 9);

        assert_eq!(view.budget_exhausted.as_deref(), Some("token limit"));
    }

    #[test]
    fn render_markdown_new_sections() {
        let events = vec![
            event(EventBody::ApprovalRequested {
                intent_id: "i1".into(),
                tool: "redhands_scan".into(),
                request_id: "req-1".into(),
            }),
            event(EventBody::ApprovalDecisionRecorded {
                intent_id: "i1".into(),
                approved: true,
                decided_by: "operator".into(),
            }),
            event(EventBody::ApprovalRequested {
                intent_id: "i2".into(),
                tool: "redhands_exec".into(),
                request_id: "req-2".into(),
            }),
            event(EventBody::FindingVerified {
                finding_id: "f1".into(),
                verdict: "confirmed".into(),
                evidence_seq: 7,
            }),
            event(EventBody::BudgetExhausted {
                reason: "token limit".into(),
            }),
        ];
        let md = render_markdown(&project(&events));

        assert!(md.contains("## Approvals"));
        assert!(md.contains("| Intent | Tool | Approved | Decided by |"));
        assert!(md.contains("| i1 | redhands_scan | yes | operator |"));
        assert!(md.contains("| i2 | redhands_exec | pending | (pending) |"));
        assert!(md.contains("## Verification"));
        assert!(md.contains("- **f1** → confirmed → ledger event #7"));
        assert!(md.contains("- **Budget exhausted:** token limit"));

        // Existing sections remain intact.
        assert!(md.contains("## Intents"));
        assert!(md.contains("## Findings"));
        assert!(md.contains("## Tool evidence"));
    }

    #[test]
    fn render_markdown_omits_new_sections_when_empty() {
        let view = project(&[event(EventBody::EngagementStarted {
            goal: "g".into(),
            redhands_version: "v".into(),
        })]);
        let md = render_markdown(&view);
        assert!(!md.contains("## Approvals"));
        assert!(!md.contains("## Verification"));
        assert!(!md.contains("Budget exhausted"));
    }
}

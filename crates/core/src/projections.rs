use crate::events::{EventBody, StoredEvent};
use serde::{Deserialize, Serialize};

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

/// An evidence blob snapshot together with the ledger call it came from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceView {
    pub intent_id: String,
    pub tool: String,
    pub hash: String,
    pub seq: i64,
}

/// The result of re-running a tool to check a finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetestView {
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
    pub evidence: Vec<EvidenceView>,
    pub retests: Vec<RetestView>,
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
                // If an id was reused, the decision belongs to the most
                // recently created intent with that id.
                if let Some(intent) = view.intents.iter_mut().rev().find(|i| &i.id == intent_id) {
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
                // A decision refers to the latest request for this intent.
                // Updating the first match would leave a newer request pending
                // whenever an intent id is reused (e.g. a retry).
                if let Some(approval) = view
                    .approvals
                    .iter_mut()
                    .rev()
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
            EventBody::EvidenceStored {
                intent_id,
                tool,
                hash,
                seq,
            } => {
                view.evidence.push(EvidenceView {
                    intent_id: intent_id.clone(),
                    tool: tool.clone(),
                    hash: hash.clone(),
                    seq: *seq,
                });
            }
            EventBody::FindingRetested {
                finding_id,
                verdict,
                evidence_seq,
            } => {
                view.retests.push(RetestView {
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
            // Future event kinds are preserved in the ledger but have no
            // meaning in this version's views; ignore them rather than panic.
            EventBody::Unknown { .. } => {}
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

    if !view.evidence.is_empty() {
        out.push_str("## Evidence\n\n");
        out.push_str("| Tool | Hash | Ledger seq |\n|---|---|---|\n");
        for item in &view.evidence {
            out.push_str(&format!(
                "| {} | {} | {} |\n",
                item.tool, item.hash, item.seq
            ));
        }
        out.push('\n');
    }

    if !view.retests.is_empty() {
        out.push_str("## Retests\n\n");
        for retest in &view.retests {
            out.push_str(&format!(
                "- **{}** → {} → ledger event #{}\n",
                retest.finding_id, retest.verdict, retest.evidence_seq
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
    fn project_evidence_and_retest_events() {
        let hash = "ab".repeat(32);
        let events = vec![
            event(EventBody::EvidenceStored {
                intent_id: "i1".into(),
                tool: "redhands_health".into(),
                hash: hash.clone(),
                seq: 4,
            }),
            event(EventBody::FindingRetested {
                finding_id: "finding-1".into(),
                verdict: "still_reproducible".into(),
                evidence_seq: 8,
            }),
        ];
        let view = project(&events);

        assert_eq!(view.evidence.len(), 1);
        assert_eq!(view.evidence[0].intent_id, "i1");
        assert_eq!(view.evidence[0].tool, "redhands_health");
        assert_eq!(view.evidence[0].hash, hash);
        assert_eq!(view.evidence[0].seq, 4);

        assert_eq!(view.retests.len(), 1);
        assert_eq!(view.retests[0].finding_id, "finding-1");
        assert_eq!(view.retests[0].verdict, "still_reproducible");
        assert_eq!(view.retests[0].evidence_seq, 8);
    }

    #[test]
    fn render_markdown_evidence_and_retests() {
        let hash = "cd".repeat(32);
        let events = vec![
            event(EventBody::EvidenceStored {
                intent_id: "intent-1".into(),
                tool: "redhands_health".into(),
                hash: hash.clone(),
                seq: 4,
            }),
            event(EventBody::FindingRetested {
                finding_id: "finding-1".into(),
                verdict: "fixed".into(),
                evidence_seq: 8,
            }),
        ];
        let md = render_markdown(&project(&events));

        assert!(md.contains("## Evidence"));
        assert!(md.contains("| Tool | Hash | Ledger seq |"));
        assert!(md.contains(&format!("| redhands_health | {hash} | 4 |")));
        assert!(md.contains("## Retests"));
        assert!(md.contains("- **finding-1** → fixed → ledger event #8"));
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
        assert!(!md.contains("## Evidence"));
        assert!(!md.contains("## Retests"));
        assert!(!md.contains("Budget exhausted"));
    }

    #[test]
    fn decision_updates_latest_request_for_reused_intent_id() {
        let events = vec![
            event(EventBody::ApprovalRequested {
                intent_id: "i1".into(),
                tool: "first".into(),
                request_id: "req-1".into(),
            }),
            event(EventBody::ApprovalDecisionRecorded {
                intent_id: "i1".into(),
                approved: true,
                decided_by: "first-op".into(),
            }),
            event(EventBody::ApprovalRequested {
                intent_id: "i1".into(),
                tool: "second".into(),
                request_id: "req-2".into(),
            }),
            event(EventBody::ApprovalDecisionRecorded {
                intent_id: "i1".into(),
                approved: false,
                decided_by: "second-op".into(),
            }),
        ];
        let view = project(&events);
        assert_eq!(view.approvals.len(), 2);
        assert_eq!(view.approvals[0].approved, Some(true));
        assert_eq!(view.approvals[0].decided_by, "first-op");
        // The first (buggy) implementation re-wrote the first approval here,
        // leaving the newest request pending.
        assert_eq!(view.approvals[1].request_id, "req-2");
        assert_eq!(view.approvals[1].approved, Some(false));
        assert_eq!(view.approvals[1].decided_by, "second-op");

        let intents = vec![
            event(EventBody::IntentCreated {
                id: "dup".into(),
                title: "old".into(),
                tool: "x".into(),
                arguments: serde_json::json!({}),
            }),
            event(EventBody::IntentCreated {
                id: "dup".into(),
                title: "new".into(),
                tool: "x".into(),
                arguments: serde_json::json!({}),
            }),
            event(EventBody::GuardDecision {
                intent_id: "dup".into(),
                allowed: false,
                reason: "denied".into(),
            }),
        ];
        let view = project(&intents);
        assert_eq!(view.intents[0].allowed, None);
        assert_eq!(view.intents[1].title, "new");
        assert_eq!(view.intents[1].allowed, Some(false));
    }

    #[test]
    fn verification_and_retest_keep_ledger_order() {
        let events = vec![
            event(EventBody::FindingVerified {
                finding_id: "f1".into(),
                verdict: "confirmed".into(),
                evidence_seq: 1,
            }),
            event(EventBody::FindingRetested {
                finding_id: "f1".into(),
                verdict: "fixed".into(),
                evidence_seq: 2,
            }),
            event(EventBody::FindingVerified {
                finding_id: "f2".into(),
                verdict: "rejected".into(),
                evidence_seq: 3,
            }),
            event(EventBody::FindingRetested {
                finding_id: "f2".into(),
                verdict: "still_reproducible".into(),
                evidence_seq: 4,
            }),
        ];
        let view = project(&events);
        let verdicts: Vec<_> = view
            .verifications
            .iter()
            .map(|v| (v.finding_id.as_str(), v.verdict.as_str()))
            .chain(
                view.retests
                    .iter()
                    .map(|v| (v.finding_id.as_str(), v.verdict.as_str())),
            )
            .collect();
        assert_eq!(
            verdicts,
            [
                ("f1", "confirmed"),
                ("f2", "rejected"),
                ("f1", "fixed"),
                ("f2", "still_reproducible"),
            ]
        );
        let md = render_markdown(&view);
        let v_pos = md.find("confirmed").unwrap();
        let r_pos = md.find("fixed").unwrap();
        assert!(v_pos < r_pos, "markdown sections must be stable");
    }

    #[test]
    fn unknown_events_do_not_change_projections_or_panic() {
        let events = vec![
            event(EventBody::EngagementStarted {
                goal: "g".into(),
                redhands_version: "v".into(),
            }),
            event(EventBody::Unknown {
                event_kind: "future_kind".into(),
                raw: r#"{"kind":"future_kind","x":1}"#.into(),
            }),
            event(EventBody::EngagementCompleted { findings: 0 }),
        ];
        let view = project(&events);
        assert_eq!(view.goal.as_deref(), Some("g"));
        assert!(view.completed);
        assert!(view.intents.is_empty());
        assert!(render_markdown(&view).contains("completed"));
    }

    #[test]
    fn render_markdown_handles_empty_and_duplicate_ids() {
        let events = vec![
            event(EventBody::IntentCreated {
                id: "".into(),
                title: "".into(),
                tool: "".into(),
                arguments: serde_json::json!({}),
            }),
            event(EventBody::IntentCreated {
                id: "dup".into(),
                title: "dup".into(),
                tool: "x".into(),
                arguments: serde_json::json!({}),
            }),
            event(EventBody::IntentCreated {
                id: "dup".into(),
                title: "dup again".into(),
                tool: "x".into(),
                arguments: serde_json::json!({}),
            }),
            event(EventBody::FindingRecorded {
                id: "".into(),
                title: "".into(),
                severity: "".into(),
                evidence_seq: 0,
            }),
            event(EventBody::FindingRecorded {
                id: "dup".into(),
                title: "dup".into(),
                severity: "info".into(),
                evidence_seq: 1,
            }),
        ];
        let md = render_markdown(&project(&events));
        assert_eq!(md.matches("|  |  | not evaluated |").count(), 1);
        assert!(md.contains("| dup | x | not evaluated |"));
        assert!(md.contains("###  ()"));
        assert!(md.contains("### dup (info)"));
    }

    #[test]
    fn empty_projections_render_without_panicking() {
        let md = render_markdown(&project(&[]));
        assert!(md.contains("# RedAgent engagement report"));
        assert!(md.contains("_none_"));
    }
}

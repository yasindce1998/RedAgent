use crate::events::{EventBody, StoredEvent};

#[derive(Debug, Clone)]
pub struct IntentView {
    pub id: String,
    pub title: String,
    pub tool: String,
    pub allowed: Option<bool>,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct ToolCallView {
    pub intent_id: String,
    pub tool: String,
    pub content: String,
    pub is_error: bool,
}

#[derive(Debug, Clone)]
pub struct FindingView {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub evidence_seq: i64,
}

/// Read-only view over the ledger. Rebuilt from events on demand.
#[derive(Debug, Default)]
pub struct EngagementView {
    pub goal: Option<String>,
    pub redhands_version: Option<String>,
    pub intents: Vec<IntentView>,
    pub tool_calls: Vec<ToolCallView>,
    pub findings: Vec<FindingView>,
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
        "- **Goal:** {}\n- **RedHands:** {}\n- **Status:** {}\n\n",
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
}

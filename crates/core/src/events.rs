use serde::{Deserialize, Serialize};

/// The only things that can happen in an engagement. Adding a variant is a
/// deliberate schema change: old ledgers still deserialize because serde
/// ignores unknown variants only with `#[serde(other)]`, so version carefully.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventBody {
    EngagementStarted {
        goal: String,
        redhands_version: String,
    },
    IntentCreated {
        id: String,
        title: String,
        tool: String,
        arguments: serde_json::Value,
    },
    GuardDecision {
        intent_id: String,
        allowed: bool,
        reason: String,
    },
    ToolCallCompleted {
        intent_id: String,
        tool: String,
        content: String,
        is_error: bool,
    },
    FindingRecorded {
        id: String,
        title: String,
        severity: String,
        evidence_seq: i64,
    },
    EngagementCompleted {
        findings: usize,
    },
    EngagementAborted {
        reason: String,
    },
    ApprovalRequested {
        intent_id: String,
        tool: String,
        request_id: String,
    },
    ApprovalDecisionRecorded {
        intent_id: String,
        approved: bool,
        decided_by: String,
    },
    FindingVerified {
        finding_id: String,
        verdict: String,
        evidence_seq: i64,
    },
    BudgetExhausted {
        reason: String,
    },
    /// A tool output snapshot has been written to the evidence blob store.
    /// `seq` is the sequence of the `ToolCallCompleted` event it snapshots.
    EvidenceStored {
        intent_id: String,
        tool: String,
        hash: String,
        seq: i64,
    },
    /// The outcome of re-running a tool to check whether a finding still
    /// reproduces. `evidence_seq` points at the retest's `ToolCallCompleted`.
    FindingRetested {
        finding_id: String,
        verdict: String,
        evidence_seq: i64,
    },
}

impl EventBody {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::EngagementStarted { .. } => "engagement_started",
            Self::IntentCreated { .. } => "intent_created",
            Self::GuardDecision { .. } => "guard_decision",
            Self::ToolCallCompleted { .. } => "tool_call_completed",
            Self::FindingRecorded { .. } => "finding_recorded",
            Self::EngagementCompleted { .. } => "engagement_completed",
            Self::EngagementAborted { .. } => "engagement_aborted",
            Self::ApprovalRequested { .. } => "approval_requested",
            Self::ApprovalDecisionRecorded { .. } => "approval_decision_recorded",
            Self::FindingVerified { .. } => "finding_verified",
            Self::BudgetExhausted { .. } => "budget_exhausted",
            Self::EvidenceStored { .. } => "evidence_stored",
            Self::FindingRetested { .. } => "finding_retested",
        }
    }
}

/// An event as persisted in the ledger. `hash` covers seq, timestamp, payload
/// and the previous hash, forming a tamper-evident chain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredEvent {
    pub seq: i64,
    pub ts: String,
    pub body: EventBody,
    pub prev_hash: String,
    pub hash: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_event_kinds_and_ledger_tags() {
        let cases = [
            (
                EventBody::ApprovalRequested {
                    intent_id: "i1".into(),
                    tool: "t".into(),
                    request_id: "r1".into(),
                },
                "approval_requested",
            ),
            (
                EventBody::ApprovalDecisionRecorded {
                    intent_id: "i1".into(),
                    approved: true,
                    decided_by: "operator".into(),
                },
                "approval_decision_recorded",
            ),
            (
                EventBody::FindingVerified {
                    finding_id: "f1".into(),
                    verdict: "confirmed".into(),
                    evidence_seq: 7,
                },
                "finding_verified",
            ),
            (
                EventBody::BudgetExhausted {
                    reason: "token limit".into(),
                },
                "budget_exhausted",
            ),
            (
                EventBody::EvidenceStored {
                    intent_id: "i1".into(),
                    tool: "redhands_health".into(),
                    hash: "ab".repeat(32),
                    seq: 4,
                },
                "evidence_stored",
            ),
            (
                EventBody::FindingRetested {
                    finding_id: "f1".into(),
                    verdict: "still_reproducible".into(),
                    evidence_seq: 7,
                },
                "finding_retested",
            ),
        ];
        for (body, expected_kind) in cases {
            assert_eq!(body.kind(), expected_kind);
            let json = serde_json::to_value(&body).expect("serialize event");
            assert_eq!(json["kind"], expected_kind);
        }
    }

    #[test]
    fn evidence_events_round_trip_with_all_fields() {
        let bodies = [
            EventBody::EvidenceStored {
                intent_id: "i1".into(),
                tool: "redhands_health".into(),
                hash: "cd".repeat(32),
                seq: 4,
            },
            EventBody::FindingRetested {
                finding_id: "finding-1".into(),
                verdict: "fixed".into(),
                evidence_seq: 9,
            },
        ];
        for body in bodies {
            let json = serde_json::to_string(&body).expect("serialize");
            let decoded: EventBody = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(decoded, body);
        }
    }
}

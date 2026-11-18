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

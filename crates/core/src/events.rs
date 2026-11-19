use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

/// A human-readable summary of a tool call, presented to the operator when
/// approval is requested. Persisted with the `ApprovalRequested` event so a
/// report can show exactly what was about to run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallProposal {
    pub tool: String,
    /// Pretty-printed JSON arguments.
    pub arguments: String,
    /// One of `in_scope`, `out_of_scope`, `unresolvable`, `not_declared`.
    pub scope_verdict: String,
    pub risk_flags: Vec<String>,
    /// Line-based diff against the previous call to the same tool, if any.
    pub diff: Option<String>,
}

/// The only things that can happen in an engagement.
///
/// This enum deliberately supports **forward compatibility**: a ledger written
/// by a newer RedAgent can contain a `kind` this version has never seen. Such
/// events deserialize into [`EventBody::Unknown`], which keeps both the
/// original tag and the original payload string. Known kinds are still parsed
/// strictly, so a corrupted known event is not silently accepted.
///
/// Note that `#[serde(other)]` cannot be used here: serde does accept it on an
/// internally tagged enum, but only on a **unit** variant, and a unit variant
/// has nowhere to store the `kind` tag or the payload. Deserialization is
/// therefore implemented manually below.
#[derive(Debug, Clone, PartialEq, Serialize)]
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
        /// Added in a later schema; `#[serde(default)]` keeps v0.3.1 ledgers
        /// (which had no proposal) readable.
        #[serde(default)]
        proposal: Option<CallProposal>,
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
    /// A target failed the declared scope check. The tool was never called.
    ScopeDenied {
        intent_id: String,
        tool: String,
        reason: String,
    },
    /// Untrusted text that looks like a prompt-injection attempt. Detection is
    /// wired by a higher layer; the ledger only stores the signal.
    InjectionSignal {
        intent_id: String,
        source: String,
        signal: String,
        detail: String,
    },
    /// The planner produced an unusable plan, so it was rejected and retried.
    PlanRejected {
        reason: String,
        attempt: u32,
    },
    /// An event kind written by a future version of RedAgent that this reader
    /// does not recognize. `event_kind` is the original `kind` tag and `raw` is
    /// the payload as stored in the ledger. Unknown events are inert: they do
    /// not change any projection, but they are preserved verbatim so callers
    /// can verify and re-emit the ledger without data loss.
    #[serde(rename = "__redagent_unknown__")]
    Unknown {
        event_kind: String,
        raw: String,
    },
}

/// All event kinds this version understands. The wire format used by
/// [`EventBody`] and [`KnownEventBody`] must stay in sync with this list.
const KNOWN_KINDS: &[&str] = &[
    "engagement_started",
    "intent_created",
    "guard_decision",
    "tool_call_completed",
    "finding_recorded",
    "engagement_completed",
    "engagement_aborted",
    "approval_requested",
    "approval_decision_recorded",
    "finding_verified",
    "budget_exhausted",
    "evidence_stored",
    "finding_retested",
    "scope_denied",
    "injection_signal",
    "plan_rejected",
];

/// Internal tag used when serializing [`EventBody::Unknown`]. Reserved so it
/// can never collide with a real event kind.
const UNKNOWN_TAG: &str = "__redagent_unknown__";

/// The wire shape of a known event. Kept separate from [`EventBody`] so the
/// public enum can add an `Unknown` fallback variant without changing the
/// on-disk format of any known event.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum KnownEventBody {
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
        /// Added in a later schema; `#[serde(default)]` keeps v0.3.1 ledgers
        /// (which had no proposal) readable.
        #[serde(default)]
        proposal: Option<CallProposal>,
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
    EvidenceStored {
        intent_id: String,
        tool: String,
        hash: String,
        seq: i64,
    },
    FindingRetested {
        finding_id: String,
        verdict: String,
        evidence_seq: i64,
    },
    ScopeDenied {
        intent_id: String,
        tool: String,
        reason: String,
    },
    InjectionSignal {
        intent_id: String,
        source: String,
        signal: String,
        detail: String,
    },
    PlanRejected {
        reason: String,
        attempt: u32,
    },
}

impl From<KnownEventBody> for EventBody {
    fn from(event: KnownEventBody) -> Self {
        match event {
            KnownEventBody::EngagementStarted {
                goal,
                redhands_version,
            } => Self::EngagementStarted {
                goal,
                redhands_version,
            },
            KnownEventBody::IntentCreated {
                id,
                title,
                tool,
                arguments,
            } => Self::IntentCreated {
                id,
                title,
                tool,
                arguments,
            },
            KnownEventBody::GuardDecision {
                intent_id,
                allowed,
                reason,
            } => Self::GuardDecision {
                intent_id,
                allowed,
                reason,
            },
            KnownEventBody::ToolCallCompleted {
                intent_id,
                tool,
                content,
                is_error,
            } => Self::ToolCallCompleted {
                intent_id,
                tool,
                content,
                is_error,
            },
            KnownEventBody::FindingRecorded {
                id,
                title,
                severity,
                evidence_seq,
            } => Self::FindingRecorded {
                id,
                title,
                severity,
                evidence_seq,
            },
            KnownEventBody::EngagementCompleted { findings } => {
                Self::EngagementCompleted { findings }
            }
            KnownEventBody::EngagementAborted { reason } => Self::EngagementAborted { reason },
            KnownEventBody::ApprovalRequested {
                intent_id,
                tool,
                request_id,
                proposal,
            } => Self::ApprovalRequested {
                intent_id,
                tool,
                request_id,
                proposal,
            },
            KnownEventBody::ApprovalDecisionRecorded {
                intent_id,
                approved,
                decided_by,
            } => Self::ApprovalDecisionRecorded {
                intent_id,
                approved,
                decided_by,
            },
            KnownEventBody::FindingVerified {
                finding_id,
                verdict,
                evidence_seq,
            } => Self::FindingVerified {
                finding_id,
                verdict,
                evidence_seq,
            },
            KnownEventBody::BudgetExhausted { reason } => Self::BudgetExhausted { reason },
            KnownEventBody::EvidenceStored {
                intent_id,
                tool,
                hash,
                seq,
            } => Self::EvidenceStored {
                intent_id,
                tool,
                hash,
                seq,
            },
            KnownEventBody::FindingRetested {
                finding_id,
                verdict,
                evidence_seq,
            } => Self::FindingRetested {
                finding_id,
                verdict,
                evidence_seq,
            },
            KnownEventBody::ScopeDenied {
                intent_id,
                tool,
                reason,
            } => Self::ScopeDenied {
                intent_id,
                tool,
                reason,
            },
            KnownEventBody::InjectionSignal {
                intent_id,
                source,
                signal,
                detail,
            } => Self::InjectionSignal {
                intent_id,
                source,
                signal,
                detail,
            },
            KnownEventBody::PlanRejected { reason, attempt } => {
                Self::PlanRejected { reason, attempt }
            }
        }
    }
}

/// Helper carrying the serialized form of the fallback variant so that an
/// `Unknown` event survives a serialize/deserialize round trip.
#[derive(Deserialize)]
struct FallbackWire {
    event_kind: String,
    raw: String,
}

impl EventBody {
    /// Parse a payload read straight from the ledger. Unlike the generic
    /// `Deserialize` impl, this preserves the **exact original string** for
    /// unknown event kinds.
    pub(crate) fn from_payload(payload: &str) -> Result<Self, serde_json::Error> {
        let value: serde_json::Value = serde_json::from_str(payload)?;
        let kind = value
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| serde_json::Error::custom("event payload has no string `kind` tag"))?;

        if kind == UNKNOWN_TAG {
            if let Ok(wire) = serde_json::from_str::<FallbackWire>(payload) {
                return Ok(Self::Unknown {
                    event_kind: wire.event_kind,
                    raw: wire.raw,
                });
            }
        }
        if KNOWN_KINDS.contains(&kind) {
            return serde_json::from_str::<KnownEventBody>(payload).map(Into::into);
        }
        Ok(Self::Unknown {
            event_kind: kind.to_owned(),
            raw: payload.to_owned(),
        })
    }

    fn from_value(value: serde_json::Value) -> Result<Self, serde_json::Error> {
        let kind = value
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| serde_json::Error::custom("event payload has no string `kind` tag"))?
            .to_owned();

        if kind == UNKNOWN_TAG {
            if let Ok(wire) = serde_json::from_value::<FallbackWire>(value.clone()) {
                return Ok(Self::Unknown {
                    event_kind: wire.event_kind,
                    raw: wire.raw,
                });
            }
        }
        if KNOWN_KINDS.contains(&kind.as_str()) {
            return serde_json::from_value::<KnownEventBody>(value).map(Into::into);
        }
        Ok(Self::Unknown {
            event_kind: kind,
            raw: value.to_string(),
        })
    }

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
            Self::ScopeDenied { .. } => "scope_denied",
            Self::InjectionSignal { .. } => "injection_signal",
            Self::PlanRejected { .. } => "plan_rejected",
            // The original tag is preserved in `event_kind`.
            Self::Unknown { .. } => "unknown",
        }
    }
}

impl<'de> Deserialize<'de> for EventBody {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        Self::from_value(value).map_err(serde::de::Error::custom)
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
                    proposal: None,
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

    /// Every known variant must appear in `KNOWN_KINDS`, otherwise its payload
    /// would be misclassified as a future event when read back from a ledger.
    #[test]
    fn known_kinds_list_covers_every_variant() {
        let bodies = [
            EventBody::EngagementStarted {
                goal: "g".into(),
                redhands_version: "v".into(),
            },
            EventBody::IntentCreated {
                id: "i".into(),
                title: "t".into(),
                tool: "x".into(),
                arguments: serde_json::json!({}),
            },
            EventBody::GuardDecision {
                intent_id: "i".into(),
                allowed: true,
                reason: "r".into(),
            },
            EventBody::ToolCallCompleted {
                intent_id: "i".into(),
                tool: "x".into(),
                content: "c".into(),
                is_error: false,
            },
            EventBody::FindingRecorded {
                id: "f".into(),
                title: "t".into(),
                severity: "info".into(),
                evidence_seq: 1,
            },
            EventBody::EngagementCompleted { findings: 0 },
            EventBody::EngagementAborted { reason: "r".into() },
            EventBody::ApprovalRequested {
                intent_id: "i".into(),
                tool: "x".into(),
                request_id: "r".into(),
                proposal: None,
            },
            EventBody::ApprovalDecisionRecorded {
                intent_id: "i".into(),
                approved: true,
                decided_by: "op".into(),
            },
            EventBody::FindingVerified {
                finding_id: "f".into(),
                verdict: "v".into(),
                evidence_seq: 1,
            },
            EventBody::BudgetExhausted { reason: "r".into() },
            EventBody::EvidenceStored {
                intent_id: "i".into(),
                tool: "x".into(),
                hash: "ab".repeat(32),
                seq: 1,
            },
            EventBody::FindingRetested {
                finding_id: "f".into(),
                verdict: "v".into(),
                evidence_seq: 1,
            },
            EventBody::ScopeDenied {
                intent_id: "i".into(),
                tool: "x".into(),
                reason: "r".into(),
            },
            EventBody::InjectionSignal {
                intent_id: "i".into(),
                source: "tool_output".into(),
                signal: "ignore_previous".into(),
                detail: "d".into(),
            },
            EventBody::PlanRejected {
                reason: "r".into(),
                attempt: 1,
            },
        ];
        assert_eq!(bodies.len(), KNOWN_KINDS.len());
        for body in bodies {
            let kind = body.kind();
            assert!(KNOWN_KINDS.contains(&kind), "missing kind {kind}");
            let json = serde_json::to_string(&body).unwrap();
            let decoded = EventBody::from_payload(&json).unwrap();
            assert_eq!(decoded, body);
        }
    }

    #[test]
    fn future_kind_is_preserved_with_its_raw_payload() {
        // Spacing and key order are intentionally not canonical: `from_payload`
        // must keep the original bytes, not a re-serialized version.
        let payload = r#"{"future_field": 42, "kind":"tool_invoked", "id":"x" }"#;
        let body = EventBody::from_payload(payload).unwrap();
        match &body {
            EventBody::Unknown { event_kind, raw } => {
                assert_eq!(event_kind, "tool_invoked");
                assert_eq!(raw, payload);
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
        assert_eq!(body.kind(), "unknown");

        // The generic Deserialize impl cannot see the original whitespace, but
        // it still preserves the tag and a semantically identical payload.
        let decoded: EventBody = serde_json::from_str(payload).unwrap();
        match decoded {
            EventBody::Unknown { event_kind, raw } => {
                assert_eq!(event_kind, "tool_invoked");
                let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
                assert_eq!(value["future_field"], 42);
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn known_kind_with_reordered_or_unknown_fields_still_deserializes() {
        let payload =
            r#"{"redhands_version":"v","kind":"engagement_started","future":true,"goal":"g"}"#;
        let body = EventBody::from_payload(payload).unwrap();
        assert_eq!(
            body,
            EventBody::EngagementStarted {
                goal: "g".into(),
                redhands_version: "v".into(),
            }
        );
    }

    #[test]
    fn malformed_known_event_and_missing_kind_are_rejected() {
        // A known kind with a bad field is corruption, not a future event.
        let malformed = r#"{"kind":"engagement_started","goal":"g"}"#;
        assert!(EventBody::from_payload(malformed).is_err());
        let missing_tag = r#"{"goal":"g","redhands_version":"v"}"#;
        assert!(EventBody::from_payload(missing_tag).is_err());
    }

    #[test]
    fn unknown_fallback_round_trips() {
        let body = EventBody::Unknown {
            event_kind: "tool_invoked".into(),
            raw: r#"{"kind":"tool_invoked","x":1}"#.into(),
        };
        let json = serde_json::to_string(&body).unwrap();
        assert_eq!(serde_json::from_str::<EventBody>(&json).unwrap(), body);
        assert_eq!(EventBody::from_payload(&json).unwrap(), body);
    }

    #[test]
    fn stored_event_round_trips_with_future_kind() {
        let stored = StoredEvent {
            seq: 7,
            ts: "2026-01-01T00:00:00Z".into(),
            body: EventBody::Unknown {
                event_kind: "future_kind".into(),
                raw: r#"{"kind":"future_kind","x":1}"#.into(),
            },
            prev_hash: "0".repeat(64),
            hash: "1".repeat(64),
        };
        let json = serde_json::to_string(&stored).unwrap();
        assert_eq!(serde_json::from_str::<StoredEvent>(&json).unwrap(), stored);
    }

    /// Documents why `#[serde(other)]` is not used for the fallback variant:
    /// it works on internally tagged enums, but only on a unit variant, which
    /// necessarily discards the tag and all fields of the unknown event.
    #[test]
    fn serde_other_unit_variant_discards_unknown_event_data() {
        #[derive(Debug, Deserialize, PartialEq)]
        #[serde(tag = "kind", rename_all = "snake_case")]
        enum Probe {
            Known {
                value: u8,
            },
            #[serde(other)]
            Other,
        }
        let decoded: Probe = serde_json::from_str(r#"{"kind":"future_kind","value":7}"#).unwrap();
        assert_eq!(decoded, Probe::Other);
    }

    #[test]
    fn trust_events_round_trip_with_all_fields() {
        let bodies = [
            EventBody::ScopeDenied {
                intent_id: "i1".into(),
                tool: "redhands_scan".into(),
                reason: "target 192.168.1.1 is outside the declared scope".into(),
            },
            EventBody::InjectionSignal {
                intent_id: "i1".into(),
                source: "tool_output".into(),
                signal: "ignore_previous_instructions".into(),
                detail: "untrusted text tried to change the guard rules".into(),
            },
            EventBody::PlanRejected {
                reason: "planner emitted an unknown tool".into(),
                attempt: 2,
            },
        ];
        for body in bodies {
            let json = serde_json::to_string(&body).expect("serialize event");
            let decoded: EventBody = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(decoded, body);
            assert_eq!(EventBody::from_payload(&json).unwrap(), body);
            assert!(KNOWN_KINDS.contains(&body.kind()));
        }
    }

    #[test]
    fn approval_requested_round_trips_with_a_proposal() {
        let proposal = CallProposal {
            tool: "redhands_scan".into(),
            arguments: "{\n  \"host\": \"10.0.0.5\"\n}".into(),
            scope_verdict: "in_scope".into(),
            risk_flags: vec!["not_read_only".into(), "requires_approval".into()],
            diff: Some("- \"host\": \"10.0.0.4\"\n+ \"host\": \"10.0.0.5\"\n".into()),
        };
        let body = EventBody::ApprovalRequested {
            intent_id: "i1".into(),
            tool: "redhands_scan".into(),
            request_id: "req-1".into(),
            proposal: Some(proposal.clone()),
        };
        let json = serde_json::to_string(&body).unwrap();
        let decoded: EventBody = serde_json::from_str(&json).unwrap();
        match decoded {
            EventBody::ApprovalRequested { proposal: got, .. } => assert_eq!(got, Some(proposal)),
            other => panic!("expected ApprovalRequested, got {other:?}"),
        }
    }

    /// v0.3.1 ledgers have no `proposal` field. The `#[serde(default)]` on the
    /// new field must let them deserialize into `proposal: None`.
    #[test]
    fn old_approval_requested_payload_without_proposal_defaults_to_none() {
        let payload = r#"{"kind":"approval_requested","intent_id":"i1","tool":"redhands_health","request_id":"req-1"}"#;
        for body in [
            EventBody::from_payload(payload).unwrap(),
            serde_json::from_str::<EventBody>(payload).unwrap(),
        ] {
            match body {
                EventBody::ApprovalRequested { proposal, .. } => assert_eq!(proposal, None),
                other => panic!("expected ApprovalRequested, got {other:?}"),
            }
        }
    }
}

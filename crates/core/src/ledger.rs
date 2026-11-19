use std::path::Path;

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use crate::events::{EventBody, StoredEvent};

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Append-only, hash-chained event ledger backed by SQLite.
pub struct Ledger {
    conn: Connection,
}

impl Ledger {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("opening ledger at {}", path.display()))?;
        Self::initialize(conn)
    }

    pub fn in_memory() -> Result<Self> {
        Self::initialize(Connection::open_in_memory()?)
    }

    fn initialize(conn: Connection) -> Result<Self> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS events (
                seq       INTEGER PRIMARY KEY,
                ts        TEXT NOT NULL,
                payload   TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                hash      TEXT NOT NULL
             );",
        )?;
        Ok(Self { conn })
    }

    pub fn append(&self, body: &EventBody) -> Result<StoredEvent> {
        let tx = self.conn.unchecked_transaction()?;
        let max_seq: Option<i64> =
            tx.query_row("SELECT MAX(seq) FROM events", [], |row| row.get(0))?;
        let seq = max_seq
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| anyhow!("ledger sequence overflow: cannot append past seq i64::MAX"))?;
        let prev_hash: String = tx
            .query_row(
                "SELECT hash FROM events ORDER BY seq DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or_else(|| GENESIS_HASH.to_string());
        let ts = Utc::now().to_rfc3339();
        let payload = serde_json::to_string(body)?;
        let hash = compute_hash(seq, &ts, &payload, &prev_hash);

        tx.execute(
            "INSERT INTO events (seq, ts, payload, prev_hash, hash) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![seq, ts, payload, prev_hash, hash],
        )?;
        tx.commit()?;

        Ok(StoredEvent {
            seq,
            ts,
            body: body.clone(),
            prev_hash,
            hash,
        })
    }

    pub fn events(&self) -> Result<Vec<StoredEvent>> {
        let mut stmt = self
            .conn
            .prepare("SELECT seq, ts, payload, prev_hash, hash FROM events ORDER BY seq")?;
        let rows = stmt.query_map([], |row| {
            let seq: i64 = row.get(0)?;
            let ts: String = row.get(1)?;
            let payload: String = row.get(2)?;
            let prev_hash: String = row.get(3)?;
            let hash: String = row.get(4)?;
            // Use the payload parser that preserves unknown future kinds
            // (and the exact original bytes) instead of plain serde.
            let body = EventBody::from_payload(&payload).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    2,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?;
            Ok(StoredEvent {
                seq,
                ts,
                body,
                prev_hash,
                hash,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("reading ledger events")
    }

    /// Verify every hash and the link to the previous event. Returns the
    /// number of verified events.
    ///
    /// Hashes are recomputed from the **stored payload bytes**, not from a
    /// re-serialization of `EventBody`. Re-serializing can reorder keys, change
    /// number formatting or drop fields added by a newer schema, which would
    /// make a perfectly valid ledger fail verification. Reading the raw rows
    /// also means verification works for event kinds this version does not
    /// understand.
    pub fn verify_chain(&self) -> Result<usize> {
        let mut stmt = self
            .conn
            .prepare("SELECT seq, ts, payload, prev_hash, hash FROM events ORDER BY seq")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;

        let mut expected_prev = GENESIS_HASH.to_string();
        let mut verified = 0usize;
        for (index, row) in rows.enumerate() {
            let (seq, ts, payload, prev_hash, hash) =
                row.with_context(|| format!("reading event #{index} during verification"))?;
            let expected_seq = index
                .checked_add(1)
                .and_then(|n| i64::try_from(n).ok())
                .ok_or_else(|| anyhow!("ledger has more than i64::MAX events"))?;
            if seq != expected_seq {
                return Err(anyhow!(
                    "sequence gap at event {}: expected {}, found {}",
                    index + 1,
                    expected_seq,
                    seq
                ));
            }
            if prev_hash != expected_prev {
                return Err(anyhow!("broken chain at event {}", seq));
            }
            let computed = compute_hash(seq, &ts, &payload, &prev_hash);
            if computed != hash {
                return Err(anyhow!("hash mismatch at event {}", seq));
            }
            expected_prev = hash;
            verified += 1;
        }
        Ok(verified)
    }
}

fn compute_hash(seq: i64, ts: &str, payload: &str, prev_hash: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{}|{}|{}|{}", seq, ts, payload, prev_hash).as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_and_verify_chain() {
        let ledger = Ledger::in_memory().unwrap();
        ledger
            .append(&EventBody::EngagementStarted {
                goal: "health probe".into(),
                redhands_version: "v0.6.3".into(),
            })
            .unwrap();
        ledger
            .append(&EventBody::IntentCreated {
                id: "i1".into(),
                title: "health".into(),
                tool: "redhands_health".into(),
                arguments: serde_json::json!({}),
            })
            .unwrap();
        let events = ledger.events().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].seq, 1);
        assert_eq!(events[1].body.kind(), "intent_created");
        assert_eq!(ledger.verify_chain().unwrap(), 2);
    }

    /// Insert a row whose hash is computed over the exact payload bytes given.
    fn insert_raw(ledger: &Ledger, seq: i64, payload: &str, prev_hash: &str) -> String {
        let ts = "2026-01-01T00:00:00Z";
        let hash = compute_hash(seq, ts, payload, prev_hash);
        ledger
            .conn
            .execute(
                "INSERT INTO events (seq, ts, payload, prev_hash, hash) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![seq, ts, payload, prev_hash, hash],
            )
            .unwrap();
        hash
    }

    #[test]
    fn tampering_is_detected() {
        let ledger = Ledger::in_memory().unwrap();
        ledger
            .append(&EventBody::EngagementAborted {
                reason: "test".into(),
            })
            .unwrap();
        ledger
            .conn
            .execute("UPDATE events SET payload = '{}' WHERE seq = 1", [])
            .unwrap();
        assert!(ledger.verify_chain().is_err());
    }

    /// Regression: verification must hash the bytes SQLite actually stores.
    /// A payload with reordered keys and an extra field is still valid, but
    /// re-serializing `EventBody` would produce different bytes and falsely
    /// report a hash mismatch.
    #[test]
    fn verify_chain_uses_stored_payload_bytes() {
        let ledger = Ledger::in_memory().unwrap();
        let first = ledger
            .append(&EventBody::EngagementStarted {
                goal: "first".into(),
                redhands_version: "v1".into(),
            })
            .unwrap();

        let payload = r#"{"redhands_version":"v2","kind":"engagement_started","new_schema_field":true,"goal":"second"}"#;
        insert_raw(&ledger, 2, payload, &first.hash);

        assert_eq!(ledger.verify_chain().unwrap(), 2);
        let events = ledger.events().unwrap();
        assert_eq!(
            events[1].body,
            EventBody::EngagementStarted {
                goal: "second".into(),
                redhands_version: "v2".into(),
            }
        );
    }

    #[test]
    fn verify_chain_tolerates_unknown_future_kind() {
        let ledger = Ledger::in_memory().unwrap();
        let first = ledger
            .append(&EventBody::EngagementAborted {
                reason: "none".into(),
            })
            .unwrap();
        let payload = r#"{"kind":"tool_invoked_from_the_future","tool":"x","n":1}"#;
        insert_raw(&ledger, 2, payload, &first.hash);

        assert_eq!(ledger.verify_chain().unwrap(), 2);
        let events = ledger.events().unwrap();
        match &events[1].body {
            EventBody::Unknown { event_kind, raw } => {
                assert_eq!(event_kind, "tool_invoked_from_the_future");
                assert_eq!(raw, payload);
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn verify_chain_detects_broken_links_and_gaps() {
        let ledger = Ledger::in_memory().unwrap();
        ledger
            .append(&EventBody::BudgetExhausted {
                reason: "budget".into(),
            })
            .unwrap();
        // Wrong prev_hash: the row's own hash is internally consistent.
        insert_raw(
            &ledger,
            2,
            r#"{"kind":"budget_exhausted","reason":"x"}"#,
            &"1".repeat(64),
        );
        let err = ledger.verify_chain().unwrap_err().to_string();
        assert!(err.contains("broken chain at event 2"), "{err}");

        let ledger2 = Ledger::in_memory().unwrap();
        let first2 = ledger2
            .append(&EventBody::BudgetExhausted {
                reason: "budget".into(),
            })
            .unwrap();
        insert_raw(
            &ledger2,
            3,
            r#"{"kind":"budget_exhausted","reason":"x"}"#,
            &first2.hash,
        );
        let err = ledger2.verify_chain().unwrap_err().to_string();
        assert!(err.contains("sequence gap"), "{err}");
    }

    #[test]
    fn verify_chain_on_empty_ledger() {
        let ledger = Ledger::in_memory().unwrap();
        assert_eq!(ledger.verify_chain().unwrap(), 0);
    }

    #[test]
    fn append_reports_sequence_overflow_instead_of_wrapping() {
        let ledger = Ledger::in_memory().unwrap();
        insert_raw(
            &ledger,
            i64::MAX,
            r#"{"kind":"budget_exhausted","reason":"max"}"#,
            GENESIS_HASH,
        );
        let err = ledger
            .append(&EventBody::BudgetExhausted {
                reason: "next".into(),
            })
            .unwrap_err()
            .to_string();
        assert!(err.contains("sequence overflow"), "{err}");
    }
}

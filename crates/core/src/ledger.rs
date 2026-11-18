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
        let seq: i64 = tx.query_row("SELECT COALESCE(MAX(seq), 0) + 1 FROM events", [], |row| {
            row.get(0)
        })?;
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
            let body: EventBody = serde_json::from_str(&payload).map_err(|e| {
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
    pub fn verify_chain(&self) -> Result<usize> {
        let events = self.events()?;
        let mut expected_prev = GENESIS_HASH.to_string();
        for (i, event) in events.iter().enumerate() {
            if event.seq != (i as i64) + 1 {
                return Err(anyhow!("sequence gap at event {}", event.seq));
            }
            if event.prev_hash != expected_prev {
                return Err(anyhow!("broken chain at event {}", event.seq));
            }
            let payload = serde_json::to_string(&event.body)?;
            let computed = compute_hash(event.seq, &event.ts, &payload, &event.prev_hash);
            if computed != event.hash {
                return Err(anyhow!("hash mismatch at event {}", event.seq));
            }
            expected_prev = event.hash.clone();
        }
        Ok(events.len())
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
}

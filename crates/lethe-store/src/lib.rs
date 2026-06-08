//! Encrypted run-state store. SQLCipher via rusqlite (`bundled-sqlcipher`).
//!
//! The connection is keyed with `PRAGMA key` before any other statement.

use lethe_adapter::{ContentType, ItemRef, Outcome};
use rusqlite::{params, Connection};

mod state;
pub use state::{ItemState, RunState};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("serialize: {0}")]
    Serde(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// One row of the Phase-1 snapshot to persist.
#[derive(Debug, Clone)]
pub struct ItemSnapshot {
    pub item_ref: ItemRef,
    pub content_type: ContentType,
    pub created_at_secs: Option<i64>,
    /// `protected` when matched by the allow-list/pin predicate, else `pending`.
    pub state: ItemState,
}

#[derive(Debug, Clone)]
pub struct NewRun {
    pub run_id: String,
    pub platform: String,
    pub account: String,
    pub filter_json: String,
    pub started_secs: i64,
}

/// Per-state counts — the dry-run preview projection.
#[derive(Debug, Clone, Default)]
pub struct PreviewCounts {
    pub pending: u64,
    pub protected: u64,
    pub deleted: u64,
    pub skipped: u64,
    pub failed: u64,
}

pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open (or create) the encrypted DB and run migrations. `key` is the
    /// SQLCipher passphrase (derived/held by the app layer).
    pub fn open(path: &str, key: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "key", key)?;
        conn.execute_batch(include_str!("schema.sql"))?;
        Ok(Self { conn })
    }

    /// In-memory store for tests.
    pub fn open_in_memory(key: &str) -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "key", key)?;
        conn.execute_batch(include_str!("schema.sql"))?;
        Ok(Self { conn })
    }

    pub fn create_run(&self, run: &NewRun) -> Result<()> {
        self.conn.execute(
            "INSERT INTO runs (run_id, platform, account, filter_json, state, started)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                run.run_id,
                run.platform,
                run.account,
                run.filter_json,
                RunState::Enumerating.as_str(),
                run.started_secs,
            ],
        )?;
        Ok(())
    }

    pub fn set_run_state(&self, run_id: &str, state: RunState) -> Result<()> {
        self.conn.execute(
            "UPDATE runs SET state = ?1 WHERE run_id = ?2",
            params![state.as_str(), run_id],
        )?;
        Ok(())
    }

    /// Persist the immutable Phase-1 snapshot (the preview). Idempotent on
    /// (run_id, platform_id) so a re-enumerate can't duplicate rows.
    pub fn snapshot_items(&self, run_id: &str, items: &[ItemSnapshot]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT OR IGNORE INTO items
                 (run_id, platform_id, content_type, created_at, token, state)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?;
            for it in items {
                stmt.execute(params![
                    run_id,
                    it.item_ref.platform_id,
                    content_type_str(it.content_type),
                    it.created_at_secs,
                    it.item_ref.token,
                    it.state.as_str(),
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn preview_counts(&self, run_id: &str) -> Result<PreviewCounts> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT state, COUNT(*) FROM items WHERE run_id = ?1 GROUP BY state")?;
        let rows = stmt.query_map(params![run_id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        })?;
        let mut c = PreviewCounts::default();
        for row in rows {
            let (state, n) = row?;
            let n = n as u64;
            match state.as_str() {
                "pending" => c.pending = n,
                "protected" => c.protected = n,
                "deleted" => c.deleted = n,
                "skipped" => c.skipped = n,
                "failed" => c.failed = n,
                _ => {}
            }
        }
        Ok(c)
    }

    /// Phase-2: claim up to `n` rows still `pending` for the next delete batch.
    pub fn claim_pending_batch(&self, run_id: &str, n: usize) -> Result<Vec<ItemRef>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT platform_id, token FROM items
             WHERE run_id = ?1 AND state = 'pending' LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![run_id, n as i64], |r| {
            Ok(ItemRef {
                platform_id: r.get(0)?,
                token: r.get::<_, Option<String>>(1)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
    }

    /// Record batch outcomes in a single transaction (idempotent resume point).
    /// Callers map `already-gone` to `Outcome::Deleted` before this.
    pub fn record_outcomes(&mut self, run_id: &str, outcomes: &[(String, Outcome)]) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "UPDATE items SET state = ?1, attempts = attempts + 1, last_error = ?2
                 WHERE run_id = ?3 AND platform_id = ?4",
            )?;
            for (platform_id, outcome) in outcomes {
                let (state, err): (&str, Option<&str>) = match outcome {
                    Outcome::Deleted => ("deleted", None),
                    Outcome::Skipped { reason } => ("skipped", Some(reason.as_str())),
                    Outcome::Failed { reason, .. } => ("failed", Some(reason.as_str())),
                };
                stmt.execute(params![state, err, run_id, platform_id])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn save_receipt(
        &self,
        run_id: &str,
        summary_json: &str,
        public_key_hex: &str,
        signature_hex: &str,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO receipts (run_id, summary_json, public_key_hex, signature_hex)
             VALUES (?1, ?2, ?3, ?4)",
            params![run_id, summary_json, public_key_hex, signature_hex],
        )?;
        Ok(())
    }

    pub fn log(&self, run_id: &str, at_secs: i64, level: &str, message: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO activity_log (run_id, at, level, message) VALUES (?1, ?2, ?3, ?4)",
            params![run_id, at_secs, level, message],
        )?;
        Ok(())
    }
}

fn content_type_str(ct: ContentType) -> &'static str {
    match ct {
        ContentType::Post => "post",
        ContentType::Comment => "comment",
        ContentType::Reaction => "reaction",
        ContentType::Media => "media",
        ContentType::Dm => "dm",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(id: &str, state: ItemState) -> ItemSnapshot {
        ItemSnapshot {
            item_ref: ItemRef { platform_id: id.into(), token: None },
            content_type: ContentType::Post,
            created_at_secs: Some(1),
            state,
        }
    }

    #[test]
    fn snapshot_dedups_protects_and_resumes() {
        let mut s = Store::open_in_memory("k").unwrap();
        s.create_run(&NewRun {
            run_id: "r".into(),
            platform: "bluesky".into(),
            account: "a".into(),
            filter_json: "{}".into(),
            started_secs: 0,
        })
        .unwrap();

        // id "2" appears twice (re-enumerate); "3" is allow-listed.
        s.snapshot_items(
            "r",
            &[
                snap("1", ItemState::Pending),
                snap("2", ItemState::Pending),
                snap("2", ItemState::Pending),
                snap("3", ItemState::Protected),
            ],
        )
        .unwrap();

        let c = s.preview_counts("r").unwrap();
        assert_eq!(c.pending, 2, "duplicate id must dedup");
        assert_eq!(c.protected, 1);

        // Protected is never claimed for deletion.
        let batch = s.claim_pending_batch("r", 100).unwrap();
        assert_eq!(batch.len(), 2);

        s.record_outcomes(
            "r",
            &[("1".into(), Outcome::Deleted), ("2".into(), Outcome::Deleted)],
        )
        .unwrap();

        let c2 = s.preview_counts("r").unwrap();
        assert_eq!(c2.deleted, 2);
        assert_eq!(c2.pending, 0);
        assert_eq!(c2.protected, 1, "protected untouched");

        // Resume: nothing left to do (idempotent).
        assert!(s.claim_pending_batch("r", 100).unwrap().is_empty());
    }
}

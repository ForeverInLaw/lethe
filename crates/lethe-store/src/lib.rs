//! Encrypted run-state store. SQLCipher via rusqlite (`bundled-sqlcipher`).
//!
//! The connection is keyed with `PRAGMA key` before any other statement.

use lethe_adapter::{ContentType, ItemRef, MediaRef, Outcome};
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
    pub text: Option<String>,
    pub media: Vec<MediaRef>,
    /// `protected` when matched by the allow-list/pin predicate, else `pending`.
    pub state: ItemState,
}

/// Phase-2 projection: delete routing plus the immutable content captured in
/// Phase 1 for backup-before-delete.
#[derive(Debug, Clone)]
pub struct PendingItem {
    pub item_ref: ItemRef,
    pub content_type: ContentType,
    pub created_at_secs: Option<i64>,
    pub text: Option<String>,
    pub media: Vec<MediaRef>,
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
        migrate_content_columns(&conn)?;
        Ok(Self { conn })
    }

    /// In-memory store for tests.
    pub fn open_in_memory(key: &str) -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "key", key)?;
        conn.execute_batch(include_str!("schema.sql"))?;
        migrate_content_columns(&conn)?;
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
                 (run_id, platform_id, content_type, created_at, token, text, media_json, state)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?;
            for it in items {
                let media_json = serde_json::to_string(&it.media)?;
                stmt.execute(params![
                    run_id,
                    it.item_ref.platform_id,
                    content_type_str(it.content_type),
                    it.created_at_secs,
                    it.item_ref.token,
                    it.text,
                    media_json,
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
        Ok(self
            .claim_pending_items(run_id, n)?
            .into_iter()
            .map(|item| item.item_ref)
            .collect())
    }

    pub fn claim_pending_items(&self, run_id: &str, n: usize) -> Result<Vec<PendingItem>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT platform_id, token, content_type, created_at, text, media_json FROM items
             WHERE run_id = ?1 AND state = 'pending' LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![run_id, n as i64], |r| {
            let content_type: String = r.get(2)?;
            let media_json: String = r.get(5)?;
            let media = serde_json::from_str(&media_json).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    5,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?;
            let content_type = content_type_from_str(&content_type).map_err(|msg| {
                rusqlite::Error::FromSqlConversionFailure(
                    2,
                    rusqlite::types::Type::Text,
                    Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, msg)),
                )
            })?;
            Ok(PendingItem {
                item_ref: ItemRef {
                    platform_id: r.get(0)?,
                    token: r.get::<_, Option<String>>(1)?,
                },
                content_type,
                created_at_secs: r.get(3)?,
                text: r.get(4)?,
                media,
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
                    Outcome::RateLimited { .. } => ("pending", Some("rate limited")),
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

fn content_type_from_str(ct: &str) -> std::result::Result<ContentType, String> {
    match ct {
        "post" => Ok(ContentType::Post),
        "comment" => Ok(ContentType::Comment),
        "reaction" => Ok(ContentType::Reaction),
        "media" => Ok(ContentType::Media),
        "dm" => Ok(ContentType::Dm),
        _ => Err(format!("unknown content type: {ct}")),
    }
}

fn migrate_content_columns(conn: &Connection) -> Result<()> {
    if !column_exists(conn, "items", "text")? {
        conn.execute("ALTER TABLE items ADD COLUMN text TEXT", [])?;
    }
    if !column_exists(conn, "items", "media_json")? {
        conn.execute("ALTER TABLE items ADD COLUMN media_json TEXT NOT NULL DEFAULT '[]'", [])?;
    }
    Ok(())
}

fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for name in rows {
        if name? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(id: &str, state: ItemState) -> ItemSnapshot {
        ItemSnapshot {
            item_ref: ItemRef { platform_id: id.into(), token: None },
            content_type: ContentType::Post,
            created_at_secs: Some(1),
            text: Some(format!("text {id}")),
            media: vec![MediaRef { url: format!("https://cdn/{id}"), mime: Some("text/plain".into()) }],
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
        let rich = s.claim_pending_items("r", 100).unwrap();
        assert_eq!(rich[0].text.as_deref(), Some("text 1"));
        assert_eq!(rich[0].media.len(), 1);

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

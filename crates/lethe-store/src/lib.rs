//! Encrypted run-state store. SQLCipher via rusqlite (`bundled-sqlcipher`).
//!
//! The connection is keyed with `PRAGMA key` before any other statement.

use lethe_adapter::{ContentType, ItemRef, MediaRef, Outcome};
use rusqlite::{params, Connection, OptionalExtension};

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

/// One preview row as a UI lists it: what will go, or what was protected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemRow {
    pub platform_id: String,
    pub content_type: ContentType,
    pub created_at_secs: Option<i64>,
    pub text: Option<String>,
    pub protected: bool,
}

/// Which preview rows to page through. Rows that already ran are never listed.
#[derive(Debug, Clone, Copy, Default)]
pub struct ItemQuery {
    pub protected_only: bool,
    pub content_type: Option<ContentType>,
    pub offset: u32,
    pub limit: u32,
}

/// A signed receipt exactly as stored; `summary_json` is the signed payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredReceipt {
    pub run_id: String,
    pub summary_json: String,
    pub public_key_hex: String,
    pub signature_hex: String,
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

    /// Preview rows, newest first. Covers `pending` and `protected` only.
    pub fn preview_items(&self, run_id: &str, query: &ItemQuery) -> Result<Vec<ItemRow>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT platform_id, content_type, created_at, text, state FROM items
             WHERE run_id = ?1
               AND state IN ('pending', 'protected')
               AND (?2 = 0 OR state = 'protected')
               AND (?3 IS NULL OR content_type = ?3)
             ORDER BY created_at DESC, platform_id
             LIMIT ?4 OFFSET ?5",
        )?;
        let rows = stmt.query_map(
            params![
                run_id,
                query.protected_only,
                query.content_type.map(content_type_str),
                i64::from(query.limit),
                i64::from(query.offset),
            ],
            |r| {
                Ok(ItemRow {
                    platform_id: r.get(0)?,
                    content_type: parse_content_type_column(r, 1)?,
                    created_at_secs: r.get(2)?,
                    text: r.get(3)?,
                    protected: r.get::<_, String>(4)? == ItemState::Protected.as_str(),
                })
            },
        )?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// Pending rows per content type, for the preview breakdown.
    pub fn pending_type_counts(&self, run_id: &str) -> Result<Vec<(ContentType, u64)>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT content_type, COUNT(*) FROM items
             WHERE run_id = ?1 AND state = 'pending'
             GROUP BY content_type ORDER BY COUNT(*) DESC",
        )?;
        let rows = stmt.query_map(params![run_id], |r| {
            Ok((parse_content_type_column(r, 0)?, r.get::<_, i64>(1)? as u64))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// Move a preview row between `pending` and `protected`. Returns false when
    /// the row is missing or already ran, or once its run is executing: a batch may
    /// already be on its way to the platform, so the choice could no longer hold.
    pub fn set_item_protected(
        &self,
        run_id: &str,
        platform_id: &str,
        protected: bool,
    ) -> Result<bool> {
        let (from, to) = if protected {
            (ItemState::Pending, ItemState::Protected)
        } else {
            (ItemState::Protected, ItemState::Pending)
        };
        let changed = self.conn.execute(
            "UPDATE items SET state = ?1
             WHERE run_id = ?2 AND platform_id = ?3 AND state = ?4
               AND NOT EXISTS (SELECT 1 FROM runs WHERE run_id = ?2 AND state = 'executing')",
            params![to.as_str(), run_id, platform_id, from.as_str()],
        )?;
        Ok(changed == 1)
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
            let media_json: String = r.get(5)?;
            let media = serde_json::from_str(&media_json).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    5,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?;
            let content_type = parse_content_type_column(r, 2)?;
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
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
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

    /// All stored receipts, most recently signed first.
    pub fn receipts(&self) -> Result<Vec<StoredReceipt>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT run_id, summary_json, public_key_hex, signature_hex FROM receipts
             ORDER BY rowid DESC",
        )?;
        let rows = stmt.query_map([], receipt_from_row)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn receipt(&self, run_id: &str) -> Result<Option<StoredReceipt>> {
        self.conn
            .query_row(
                "SELECT run_id, summary_json, public_key_hex, signature_hex FROM receipts
                 WHERE run_id = ?1",
                params![run_id],
                receipt_from_row,
            )
            .optional()
            .map_err(Into::into)
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

fn parse_content_type_column(
    row: &rusqlite::Row<'_>,
    index: usize,
) -> rusqlite::Result<ContentType> {
    let raw: String = row.get(index)?;
    content_type_from_str(&raw).map_err(|msg| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, msg)),
        )
    })
}

fn receipt_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredReceipt> {
    Ok(StoredReceipt {
        run_id: row.get(0)?,
        summary_json: row.get(1)?,
        public_key_hex: row.get(2)?,
        signature_hex: row.get(3)?,
    })
}

fn migrate_content_columns(conn: &Connection) -> Result<()> {
    if !column_exists(conn, "items", "text")? {
        conn.execute("ALTER TABLE items ADD COLUMN text TEXT", [])?;
    }
    if !column_exists(conn, "items", "media_json")? {
        conn.execute(
            "ALTER TABLE items ADD COLUMN media_json TEXT NOT NULL DEFAULT '[]'",
            [],
        )?;
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
            item_ref: ItemRef {
                platform_id: id.into(),
                token: None,
            },
            content_type: ContentType::Post,
            created_at_secs: Some(1),
            text: Some(format!("text {id}")),
            media: vec![MediaRef {
                url: format!("https://cdn/{id}"),
                mime: Some("text/plain".into()),
            }],
            state,
        }
    }

    fn run_with(items: &[ItemSnapshot]) -> Store {
        let s = Store::open_in_memory("k").unwrap();
        s.create_run(&NewRun {
            run_id: "r".into(),
            platform: "bluesky".into(),
            account: "a".into(),
            filter_json: "{}".into(),
            started_secs: 0,
        })
        .unwrap();
        s.snapshot_items("r", items).unwrap();
        s
    }

    fn typed(id: &str, content_type: ContentType, at: i64, state: ItemState) -> ItemSnapshot {
        ItemSnapshot {
            content_type,
            created_at_secs: Some(at),
            ..snap(id, state)
        }
    }

    fn ids(rows: &[ItemRow]) -> Vec<&str> {
        rows.iter().map(|row| row.platform_id.as_str()).collect()
    }

    #[test]
    fn preview_items_page_newest_first_and_filter() {
        let s = run_with(&[
            typed("old", ContentType::Post, 1, ItemState::Pending),
            typed("mid", ContentType::Reaction, 2, ItemState::Pending),
            typed("new", ContentType::Post, 3, ItemState::Protected),
        ]);
        let all = ItemQuery {
            limit: 10,
            ..Default::default()
        };

        assert_eq!(
            ids(&s.preview_items("r", &all).unwrap()),
            ["new", "mid", "old"]
        );
        assert_eq!(
            ids(&s
                .preview_items(
                    "r",
                    &ItemQuery {
                        offset: 1,
                        limit: 1,
                        ..all
                    }
                )
                .unwrap()),
            ["mid"]
        );
        assert_eq!(
            ids(&s
                .preview_items(
                    "r",
                    &ItemQuery {
                        content_type: Some(ContentType::Reaction),
                        ..all
                    }
                )
                .unwrap()),
            ["mid"]
        );
        let protected = s
            .preview_items(
                "r",
                &ItemQuery {
                    protected_only: true,
                    ..all
                },
            )
            .unwrap();
        assert_eq!(ids(&protected), ["new"]);
        assert!(protected[0].protected);
    }

    #[test]
    fn preview_items_hide_rows_that_already_ran() {
        let mut s = run_with(&[snap("1", ItemState::Pending), snap("2", ItemState::Pending)]);
        s.record_outcomes("r", &[("1".into(), Outcome::Deleted)])
            .unwrap();
        let rows = s
            .preview_items(
                "r",
                &ItemQuery {
                    limit: 10,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(ids(&rows), ["2"]);
    }

    #[test]
    fn pending_type_counts_ignore_protected_rows() {
        let s = run_with(&[
            typed("a", ContentType::Post, 1, ItemState::Pending),
            typed("b", ContentType::Post, 2, ItemState::Pending),
            typed("c", ContentType::Reaction, 3, ItemState::Pending),
            typed("d", ContentType::Reaction, 4, ItemState::Protected),
        ]);
        assert_eq!(
            s.pending_type_counts("r").unwrap(),
            [(ContentType::Post, 2), (ContentType::Reaction, 1)]
        );
    }

    #[test]
    fn protecting_a_row_keeps_it_from_the_delete_batch() {
        let s = run_with(&[snap("1", ItemState::Pending), snap("2", ItemState::Pending)]);
        assert!(s.set_item_protected("r", "1", true).unwrap());

        let claimed = s.claim_pending_batch("r", 10).unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].platform_id, "2");

        assert!(s.set_item_protected("r", "1", false).unwrap());
        assert_eq!(s.claim_pending_batch("r", 10).unwrap().len(), 2);
    }

    #[test]
    fn protecting_never_rewrites_a_finished_outcome() {
        let mut s = run_with(&[snap("1", ItemState::Pending)]);
        s.record_outcomes("r", &[("1".into(), Outcome::Deleted)])
            .unwrap();
        assert!(!s.set_item_protected("r", "1", true).unwrap());
        assert!(!s.set_item_protected("r", "1", false).unwrap());
        assert_eq!(s.preview_counts("r").unwrap().deleted, 1);
    }

    #[test]
    fn protection_is_locked_once_the_run_executes() {
        let s = run_with(&[
            snap("1", ItemState::Pending),
            snap("2", ItemState::Protected),
        ]);
        s.set_run_state("r", RunState::Executing).unwrap();

        assert!(!s.set_item_protected("r", "1", true).unwrap());
        assert!(!s.set_item_protected("r", "2", false).unwrap());
        let counts = s.preview_counts("r").unwrap();
        assert_eq!((counts.pending, counts.protected), (1, 1));
    }

    #[test]
    fn receipts_read_back_newest_first() {
        let s = run_with(&[]);
        s.create_run(&NewRun {
            run_id: "r2".into(),
            platform: "bluesky".into(),
            account: "a".into(),
            filter_json: "{}".into(),
            started_secs: 0,
        })
        .unwrap();
        s.save_receipt("r", "{\"n\":1}", "pk", "sig1").unwrap();
        s.save_receipt("r2", "{\"n\":2}", "pk", "sig2").unwrap();

        let all = s.receipts().unwrap();
        assert_eq!(all[0].run_id, "r2");
        assert_eq!(all[1].signature_hex, "sig1");
        assert_eq!(s.receipt("r").unwrap().unwrap().summary_json, "{\"n\":1}");
        assert_eq!(s.receipt("missing").unwrap(), None);
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
            &[
                ("1".into(), Outcome::Deleted),
                ("2".into(), Outcome::Deleted),
            ],
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

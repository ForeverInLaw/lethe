//! Encrypted run-state store. SQLCipher via rusqlite (`bundled-sqlcipher`).
//!
//! The connection is keyed with `PRAGMA key` before any other statement.

use lethe_adapter::{ContentType, DeleteReach, ItemRef, MediaRef, Outcome, PlatformRecord};
use rusqlite::{params, Connection, OptionalExtension};

mod state;
mod unsaved_files;
pub use state::{FileFailure, ItemState, RunState};
pub use unsaved_files::{FileRetryRun, UnsavedFiles, UnsavedItem};

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
    pub platform_record: Option<PlatformRecord>,
    pub backup_gap: Option<String>,
    pub delete_reach: DeleteReach,
    /// `protected` when matched by the allow-list/pin predicate, `undeletable` when the
    /// platform will not delete it, else `pending`.
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
    pub platform_record: Option<PlatformRecord>,
    pub backup_gap: Option<String>,
    pub delete_reach: DeleteReach,
}

#[derive(Debug, Clone)]
pub struct NewRun {
    pub run_id: String,
    pub platform: String,
    pub account: String,
    pub filter_json: String,
    pub started_secs: i64,
}

/// Files still to be archived for a run, as far as Phase 1 knows their sizes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PendingMedia {
    pub bytes: u64,
    pub largest_bytes: u64,
}

/// Per-state counts — the dry-run preview projection.
#[derive(Debug, Clone, Default)]
pub struct PreviewCounts {
    pub pending: u64,
    pub protected: u64,
    pub deleted: u64,
    pub skipped: u64,
    pub failed: u64,
    pub undeletable: u64,
}

/// Rows waiting to run that go only if the person agrees, and how many need both
/// agreements, so a screen can tell what stays under any choice.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PendingConsents {
    pub backup_gaps: u64,
    pub only_for_self: u64,
    pub both: u64,
}

/// One preview row as a UI lists it: what will go, or what was protected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemRow {
    pub platform_id: String,
    pub content_type: ContentType,
    pub created_at_secs: Option<i64>,
    pub text: Option<String>,
    pub protected: bool,
    pub only_for_self: bool,
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

/// A run that started deleting and never got a receipt: stopped, failed or cut
/// short by a crash. Its backup is the only copy of what it deleted so far.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunWithoutReceipt {
    pub run_id: String,
    pub platform: String,
    pub account: String,
    pub started_secs: i64,
    pub deleted: u64,
    /// How many of `deleted` other people can still see.
    pub deleted_only_for_self: u64,
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

    /// Dates the run by the moment it begins deleting. It was created at the preview,
    /// which can be long before.
    pub fn set_run_started(&self, run_id: &str, started_secs: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE runs SET started = ?1 WHERE run_id = ?2",
            params![started_secs, run_id],
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
                 (run_id, platform_id, content_type, created_at, token, text, media_json,
                  platform_record, backup_gap, delete_reach, state)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
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
                    it.platform_record.as_ref().map(PlatformRecord::as_json),
                    it.backup_gap,
                    state::reach_as_str(it.delete_reach),
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
                "undeletable" => c.undeletable = n,
                _ => {}
            }
        }
        Ok(c)
    }

    pub fn pending_media(&self, run_id: &str) -> Result<PendingMedia> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT COALESCE(SUM(json_extract(file.value, '$.size')), 0),
                    COALESCE(MAX(json_extract(file.value, '$.size')), 0)
             FROM items, json_each(items.media_json) AS file
             WHERE items.run_id = ?1 AND items.state = 'pending'",
        )?;
        Ok(stmt.query_row(params![run_id], |r| {
            Ok(PendingMedia {
                bytes: r.get::<_, i64>(0)? as u64,
                largest_bytes: r.get::<_, i64>(1)? as u64,
            })
        })?)
    }

    pub fn pending_consents(&self, run_id: &str) -> Result<PendingConsents> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT COALESCE(SUM(backup_gap IS NOT NULL), 0),
                    COALESCE(SUM(delete_reach = 'only_for_self'), 0),
                    COALESCE(SUM(backup_gap IS NOT NULL AND delete_reach = 'only_for_self'), 0)
             FROM items WHERE run_id = ?1 AND state = 'pending'",
        )?;
        Ok(stmt.query_row(params![run_id], |r| {
            Ok(PendingConsents {
                backup_gaps: r.get::<_, i64>(0)? as u64,
                only_for_self: r.get::<_, i64>(1)? as u64,
                both: r.get::<_, i64>(2)? as u64,
            })
        })?)
    }

    /// Keeps the rows the backup cannot hold in full, for a person who did not agree
    /// to losing part of them.
    pub fn protect_backup_gaps(&self, run_id: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE items SET state = ?1
             WHERE run_id = ?2 AND state = 'pending' AND backup_gap IS NOT NULL",
            params![ItemState::Protected.as_str(), run_id],
        )?;
        Ok(())
    }

    /// Keeps the rows only this account would stop seeing, for a person who did not
    /// agree to leave them with everyone else.
    pub fn protect_only_for_self(&self, run_id: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE items SET state = ?1
             WHERE run_id = ?2 AND state = 'pending' AND delete_reach = 'only_for_self'",
            params![ItemState::Protected.as_str(), run_id],
        )?;
        Ok(())
    }

    /// Preview rows, newest first. Covers `pending` and `protected` only.
    pub fn preview_items(&self, run_id: &str, query: &ItemQuery) -> Result<Vec<ItemRow>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT platform_id, content_type, created_at, text, state, delete_reach FROM items
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
                    only_for_self: state::reach_from_stored(&r.get::<_, String>(5)?)
                        == DeleteReach::OnlyForSelf,
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
            "SELECT platform_id, token, content_type, created_at, text, media_json,
                    platform_record, backup_gap, delete_reach FROM items
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
            let platform_record = r
                .get::<_, Option<String>>(6)?
                .map(PlatformRecord::from_json)
                .transpose()
                .map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        6,
                        rusqlite::types::Type::Text,
                        Box::new(e),
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
                platform_record,
                backup_gap: r.get(7)?,
                delete_reach: state::reach_from_stored(&r.get::<_, String>(8)?),
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// Record batch outcomes in a single transaction (idempotent resume point).
    /// Callers map `already-gone` to `Outcome::Deleted` before this. A row that ran
    /// no longer needs its platform record, which can hold contacts and locations.
    pub fn record_outcomes(&mut self, run_id: &str, outcomes: &[(String, Outcome)]) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "UPDATE items SET state = ?1, attempts = attempts + 1, last_error = ?2,
                    platform_record = CASE WHEN ?1 = 'pending' THEN platform_record END
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
                if state != ItemState::Pending.as_str() {
                    unsaved_files::forget_earlier_records(&tx, run_id, platform_id)?;
                }
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

    /// Runs past the preview that have no receipt, most recently started first.
    pub fn runs_without_receipt(&self) -> Result<Vec<RunWithoutReceipt>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT r.run_id, r.platform, r.account, r.started,
                    (SELECT COUNT(*) FROM items i WHERE i.run_id = r.run_id AND i.state = 'deleted'),
                    (SELECT COUNT(*) FROM items i WHERE i.run_id = r.run_id AND i.state = 'deleted'
                        AND i.delete_reach = 'only_for_self')
             FROM runs r
             WHERE r.state NOT IN ('enumerating', 'preview')
               AND NOT EXISTS (SELECT 1 FROM receipts c WHERE c.run_id = r.run_id)
             ORDER BY r.started DESC, r.rowid DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(RunWithoutReceipt {
                run_id: row.get(0)?,
                platform: row.get(1)?,
                account: row.get(2)?,
                started_secs: row.get(3)?,
                deleted: row.get::<_, i64>(4)? as u64,
                deleted_only_for_self: row.get::<_, i64>(5)? as u64,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
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
    if !column_exists(conn, "items", "platform_record")? {
        conn.execute("ALTER TABLE items ADD COLUMN platform_record TEXT", [])?;
    }
    if !column_exists(conn, "items", "backup_gap")? {
        conn.execute("ALTER TABLE items ADD COLUMN backup_gap TEXT", [])?;
    }
    if !column_exists(conn, "items", "file_failure")? {
        conn.execute("ALTER TABLE items ADD COLUMN file_failure TEXT", [])?;
    }
    if !column_exists(conn, "items", "delete_reach")? {
        conn.execute(
            "ALTER TABLE items ADD COLUMN delete_reach TEXT NOT NULL DEFAULT 'everyone'",
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
                file_name: None,
                size: None,
            }],
            platform_record: None,
            backup_gap: None,
            delete_reach: DeleteReach::Everyone,
            state,
        }
    }

    fn run(id: &str) -> NewRun {
        NewRun {
            run_id: id.into(),
            platform: "bluesky".into(),
            account: "a".into(),
            filter_json: "{}".into(),
            started_secs: 0,
        }
    }

    fn run_with(items: &[ItemSnapshot]) -> Store {
        let s = Store::open_in_memory("k").unwrap();
        s.create_run(&run("r")).unwrap();
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
    fn runs_past_the_preview_without_a_receipt_are_listed_with_what_they_deleted() {
        let mut s = Store::open_in_memory("k").unwrap();
        for (id, started, state) in [
            ("previewed", 1, RunState::Preview),
            ("receipted", 2, RunState::Executing),
            ("older", 3, RunState::Executing),
            ("stopped", 4, RunState::Executing),
        ] {
            s.create_run(&NewRun { started_secs: started, ..run(id) }).unwrap();
            s.set_run_state(id, state).unwrap();
        }
        s.snapshot_items("stopped", &[snap("gone", ItemState::Pending), snap("left", ItemState::Pending)])
            .unwrap();
        s.record_outcomes("stopped", &[("gone".to_owned(), Outcome::Deleted)]).unwrap();
        s.save_receipt("receipted", "{}", "pub", "sig").unwrap();

        let runs = s.runs_without_receipt().unwrap();

        assert_eq!(
            runs,
            [
                RunWithoutReceipt {
                    run_id: "stopped".into(),
                    platform: "bluesky".into(),
                    account: "a".into(),
                    started_secs: 4,
                    deleted: 1,
                    deleted_only_for_self: 0,
                },
                RunWithoutReceipt {
                    run_id: "older".into(),
                    platform: "bluesky".into(),
                    account: "a".into(),
                    started_secs: 3,
                    deleted: 0,
                    deleted_only_for_self: 0,
                },
            ]
        );
    }

    #[test]
    fn a_run_is_dated_by_when_it_began_deleting_not_by_its_preview() {
        let s = Store::open_in_memory("k").unwrap();
        s.create_run(&NewRun { started_secs: 1, ..run("r") }).unwrap();
        s.set_run_state("r", RunState::Executing).unwrap();

        s.set_run_started("r", 9).unwrap();

        assert_eq!(s.runs_without_receipt().unwrap()[0].started_secs, 9);
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

    fn record(json: &str) -> PlatformRecord {
        PlatformRecord::from_json(json.into()).unwrap()
    }

    #[test]
    fn a_platform_record_stays_until_its_item_ran() {
        let mut s = Store::open_in_memory("k").unwrap();
        s.create_run(&run("r")).unwrap();
        let mut limited = snap("limited", ItemState::Pending);
        limited.platform_record = Some(record(r#"{"poll":"tea or coffee"}"#));
        let mut deleted = snap("deleted", ItemState::Pending);
        deleted.platform_record = Some(record(r#"{"contact":"+0"}"#));
        s.snapshot_items("r", &[limited, deleted, snap("plain", ItemState::Pending)])
            .unwrap();

        let claimed = s.claim_pending_items("r", 10).unwrap();
        let of = |id: &str| claimed.iter().find(|item| item.item_ref.platform_id == id).unwrap();
        assert_eq!(of("limited").platform_record, Some(record(r#"{"poll":"tea or coffee"}"#)));
        assert_eq!(of("plain").platform_record, None);

        s.record_outcomes(
            "r",
            &[
                ("limited".into(), Outcome::RateLimited { retry_after_secs: 1 }),
                ("deleted".into(), Outcome::Deleted),
            ],
        )
        .unwrap();

        let claimed = s.claim_pending_items("r", 10).unwrap();
        let limited = claimed.iter().find(|item| item.item_ref.platform_id == "limited").unwrap();
        assert!(limited.platform_record.is_some(), "it still has to reach the backup");
        let left: Option<String> = s
            .conn
            .query_row(
                "SELECT platform_record FROM items WHERE platform_id = 'deleted'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(left, None, "the local database must not outlive the delete");
    }

    #[test]
    fn items_the_backup_cannot_hold_can_be_kept_as_protected() {
        let s = Store::open_in_memory("k").unwrap();
        s.create_run(&run("r")).unwrap();
        let mut gap = snap("gap", ItemState::Pending);
        gap.backup_gap = Some("no file".into());
        let mut chosen = snap("chosen", ItemState::Protected);
        chosen.backup_gap = Some("no file".into());
        s.snapshot_items("r", &[gap, chosen, snap("whole", ItemState::Pending)])
            .unwrap();
        assert_eq!(s.pending_consents("r").unwrap().backup_gaps, 1);

        s.protect_backup_gaps("r").unwrap();

        let counts = s.preview_counts("r").unwrap();
        assert_eq!((counts.pending, counts.protected), (1, 2));
        assert_eq!(s.pending_consents("r").unwrap().backup_gaps, 0);
    }

    #[test]
    fn a_database_from_before_platform_records_gains_the_columns() {
        let path = std::env::temp_dir().join(format!("lethe-store-{}", std::process::id()));
        let path = path.to_str().unwrap();
        {
            let conn = Connection::open(path).unwrap();
            conn.pragma_update(None, "key", "k").unwrap();
            conn.execute_batch(include_str!("schema.sql")).unwrap();
            conn.execute_batch(
                "ALTER TABLE items DROP COLUMN platform_record;
                 ALTER TABLE items DROP COLUMN backup_gap;
                 INSERT INTO runs (run_id, platform, account, filter_json, state, started)
                 VALUES ('r', 'p', 'a', '{}', 'preview', 0);
                 INSERT INTO items (run_id, platform_id, content_type, state)
                 VALUES ('r', 'old', 'post', 'pending');",
            )
            .unwrap();
        }

        let s = Store::open(path, "k").unwrap();
        let claimed = s.claim_pending_items("r", 10).unwrap();
        std::fs::remove_file(path).unwrap();

        assert_eq!(claimed[0].platform_record, None);
        assert_eq!(claimed[0].backup_gap, None);
    }

    #[test]
    fn pending_media_sizes_only_files_that_will_be_archived() {
        let sized = |id: &str, state: ItemState, sizes: &[Option<u64>]| ItemSnapshot {
            media: sizes
                .iter()
                .map(|size| MediaRef {
                    url: format!("file-{id}"),
                    mime: None,
                    file_name: None,
                    size: *size,
                })
                .collect(),
            ..snap(id, state)
        };
        let s = run_with(&[
            sized("a", ItemState::Pending, &[Some(100), Some(700)]),
            sized("b", ItemState::Pending, &[None]),
            sized("c", ItemState::Protected, &[Some(9_000)]),
            sized("d", ItemState::Pending, &[]),
        ]);

        let media = s.pending_media("r").unwrap();

        assert_eq!(media.bytes, 800);
        assert_eq!(media.largest_bytes, 700);
    }

    #[test]
    fn pending_media_is_empty_for_a_run_without_files() {
        let s = run_with(&[]);
        assert_eq!(s.pending_media("r").unwrap(), PendingMedia::default());
    }
}

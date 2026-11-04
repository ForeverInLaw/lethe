//! Items that stayed on the platform because their file could not be saved, and
//! the follow-up run that tries them again. Such a row keeps its content until a
//! later run of the same account gets to the item, because the backup still needs
//! it. Then the later run holds the item, and the earlier row goes.

use rusqlite::{params, Connection};

use crate::state::{FileFailure, ItemState, RunState};
use crate::{file_facts, Result, Store};

/// A row that stayed because its file did not reach the backup, so a retry still
/// needs all of its content.
pub(crate) const WAITS_ON_A_FILE: &str = "items.state = 'failed' AND items.file_failure IS NOT NULL";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsavedItem {
    pub platform_id: String,
    pub subtype: Option<String>,
    pub created_at_secs: Option<i64>,
    pub text: Option<String>,
    /// The name of its first named file, which stands in for missing text.
    pub file_name: Option<String>,
    pub failure: FileFailure,
}

/// The last row of a page of `Store::unsaved_items`; the next page starts past it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct UnsavedCursor {
    pub created_at_secs: Option<i64>,
    pub platform_id: String,
}

/// How much stayed in a run because of its files. `Store::unsaved_items` lists it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct UnsavedFiles {
    pub total: u64,
    /// How many of them may go without the file, with the person's consent.
    pub unavailable: u64,
}

/// The follow-up run made for a retry, in preview.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRetryRun {
    pub platform: String,
    pub account: String,
    pub items: u64,
}

impl Store {
    /// Marks items as stayed because a file did not reach the backup.
    pub fn record_file_failures(
        &mut self,
        run_id: &str,
        failures: &[(String, FileFailure, String)],
    ) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "UPDATE items SET state = ?1, file_failure = ?2, last_error = ?3, attempts = attempts + 1
                 WHERE run_id = ?4 AND platform_id = ?5",
            )?;
            for (platform_id, failure, reason) in failures {
                stmt.execute(params![
                    ItemState::Failed.as_str(),
                    failure.as_str(),
                    reason,
                    run_id,
                    platform_id
                ])?;
                drop_earlier_copies(&tx, run_id, platform_id)?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn unsaved_files(&self, run_id: &str) -> Result<UnsavedFiles> {
        Ok(self.conn.query_row(
            &format!(
                "SELECT COUNT(*), COALESCE(SUM(items.file_failure = 'unavailable'), 0)
                 FROM items WHERE items.run_id = ?1 AND {WAITS_ON_A_FILE}"
            ),
            params![run_id],
            |r| Ok(UnsavedFiles { total: r.get::<_, i64>(0)? as u64, unavailable: r.get::<_, i64>(1)? as u64 }),
        )?)
    }

    /// One page of what stayed in a run because of its files, newest first and
    /// undated last. It starts just past `after`, so rows a retry settles meanwhile
    /// shift nothing.
    pub fn unsaved_items(
        &self,
        run_id: &str,
        after: Option<&UnsavedCursor>,
        limit: u32,
    ) -> Result<Vec<UnsavedItem>> {
        // The order as a row value that only grows: undated after dated, newer
        // before older, then by id.
        let mut stmt = self.conn.prepare(&format!(
            "SELECT platform_id, created_at, text, file_failure, subtype, {} FROM items
             WHERE items.run_id = ?1 AND {WAITS_ON_A_FILE}
               AND (?3 IS NULL OR (created_at IS NULL, -IFNULL(created_at, 0), platform_id) > (?4, -?5, ?3))
             ORDER BY created_at IS NULL, created_at DESC, platform_id LIMIT ?2",
            file_facts::FILE_NAME
        ))?;
        let undated = after.map(|cursor| cursor.created_at_secs.is_none());
        let created_at = after.map(|cursor| cursor.created_at_secs.unwrap_or(0));
        let platform_id = after.map(|cursor| cursor.platform_id.as_str());
        let items = stmt
            .query_map(params![run_id, limit, platform_id, undated, created_at], |r| {
                Ok(UnsavedItem {
                    platform_id: r.get(0)?,
                    subtype: r.get(4)?,
                    created_at_secs: r.get(1)?,
                    text: r.get(2)?,
                    file_name: r.get(5)?,
                    failure: FileFailure::from_stored(&r.get::<_, String>(3)?),
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(items)
    }

    /// Opens a new run holding what stayed in `from_run_id`, ready to execute. The
    /// original run keeps listing an item until the new one gets to it, so a retry
    /// that never starts loses nothing.
    pub fn retry_unsaved_files(
        &self,
        from_run_id: &str,
        new_run_id: &str,
        started_secs: i64,
    ) -> Result<FileRetryRun> {
        let tx = self.conn.unchecked_transaction()?;
        let (platform, account): (String, String) = tx.query_row(
            "SELECT platform, account FROM runs WHERE run_id = ?1",
            params![from_run_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        tx.execute(
            "INSERT INTO runs (run_id, platform, account, filter_json, state, started)
             SELECT ?2, platform, account, filter_json, ?3, ?4 FROM runs WHERE run_id = ?1",
            params![from_run_id, new_run_id, RunState::Preview.as_str(), started_secs],
        )?;
        let items = tx.execute(
            &format!(
                "INSERT INTO items (run_id, platform_id, content_type, created_at, token, text, media_json,
                                    platform_record, backup_gap, delete_reach, scope_id, subtype, state)
                 SELECT ?2, platform_id, content_type, created_at, token, text, media_json,
                        platform_record, backup_gap, delete_reach, scope_id, subtype, ?3
                 FROM items WHERE items.run_id = ?1 AND {WAITS_ON_A_FILE}"
            ),
            params![from_run_id, new_run_id, ItemState::Pending.as_str()],
        )?;
        tx.commit()?;
        Ok(FileRetryRun { platform, account, items: items as u64 })
    }

    /// Removes a retry that could not start, with the copies of the records it took.
    pub fn discard_retry(&self, run_id: &str) -> Result<()> {
        self.conn.execute("DELETE FROM runs WHERE run_id = ?1", params![run_id])?;
        Ok(())
    }
}

/// The earlier runs of the same account as run `this`.
const EARLIER_RUNS: &str = "SELECT earlier.run_id FROM runs this
    JOIN runs earlier ON earlier.rowid < this.rowid
        AND earlier.platform = this.platform AND earlier.account = this.account";

/// Once run `run_id` has dealt with an item, the earlier runs of the account that
/// kept it for want of a file no longer need their row of it.
pub(crate) fn drop_earlier_copies(conn: &Connection, run_id: &str, platform_id: &str) -> Result<()> {
    conn.prepare_cached(&format!(
        "DELETE FROM items WHERE platform_id = ?2 AND file_failure IS NOT NULL
           AND run_id IN ({EARLIER_RUNS} WHERE this.run_id = ?1)"
    ))?
    .execute(params![run_id, platform_id])?;
    Ok(())
}

/// The same copies, for every item a later run already dealt with: older versions
/// kept them.
pub(crate) fn drop_copies_older_versions_kept(conn: &Connection) -> Result<()> {
    conn.execute(
        &format!(
            "DELETE FROM items WHERE file_failure IS NOT NULL AND run_id IN (
                {EARLIER_RUNS}
                JOIN items settled ON settled.run_id = this.run_id AND settled.platform_id = items.platform_id
                WHERE settled.state IN ('deleted', 'skipped', 'failed')
             )"
        ),
        [],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ItemSnapshot, NewRun};
    use lethe_adapter::{ContentType, ItemRef, MediaRef, Outcome, PlatformRecord};

    const ACCOUNT: &str = "acc";

    fn store() -> Store {
        Store::open_in_memory("test-key").unwrap()
    }

    fn run_of(store: &Store, run_id: &str, account: &str, ids: &[&str]) {
        store
            .create_run(&NewRun {
                run_id: run_id.into(),
                platform: "bluesky".into(),
                account: account.into(),
                filter_json: "{\"kept\":true}".into(),
                started_secs: 10,
            })
            .unwrap();
        let rows: Vec<_> = ids
            .iter()
            .map(|id| ItemSnapshot {
                item_ref: ItemRef { platform_id: (*id).into(), token: Some(format!("token-{id}")) },
                content_type: ContentType::Post,
                subtype: None,
                created_at_secs: Some(100),
                text: Some(format!("text of {id}")),
                media: vec![MediaRef {
                    url: "blob".into(),
                    mime: None,
                    file_name: Some("photo.jpg".into()),
                    size: Some(7),
                }],
                platform_record: Some(PlatformRecord::from_json(format!("{{\"id\":\"{id}\"}}")).unwrap()),
                backup_gap: Some("poll votes are missing".into()),
                delete_reach: lethe_adapter::DeleteReach::Everyone,
                scope_id: None,
                state: ItemState::Pending,
            })
            .collect();
        store.snapshot_items(run_id, &rows).unwrap();
    }

    fn fail(store: &mut Store, run_id: &str, id: &str, failure: FileFailure) {
        store
            .record_file_failures(run_id, &[(id.into(), failure, "not backed up".into())])
            .unwrap();
    }

    fn listed(store: &Store, run_id: &str) -> Vec<String> {
        let items = store.unsaved_items(run_id, None, 50).unwrap();
        items.into_iter().map(|item| item.platform_id).collect()
    }

    #[test]
    fn a_run_lists_only_what_stayed_because_of_a_file() {
        let mut store = store();
        run_of(&store, "r1", ACCOUNT, &["file", "network", "refused", "gone"]);
        fail(&mut store, "r1", "file", FileFailure::Unavailable);
        fail(&mut store, "r1", "network", FileFailure::Unreachable);
        store
            .record_outcomes(
                "r1",
                &[
                    ("refused".into(), Outcome::Failed { reason: "denied".into(), retryable: false }),
                    ("gone".into(), Outcome::Deleted),
                ],
            )
            .unwrap();

        let unsaved = store.unsaved_files("r1").unwrap();
        let items = store.unsaved_items("r1", None, 50).unwrap();

        assert_eq!((unsaved.total, unsaved.unavailable), (2, 1));
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].platform_id, "file");
        assert_eq!(items[0].failure, FileFailure::Unavailable);
        assert_eq!(items[0].text.as_deref(), Some("text of file"));
        assert_eq!(items[0].file_name.as_deref(), Some("photo.jpg"));
        assert_eq!(items[1].failure, FileFailure::Unreachable);
    }

    #[test]
    fn a_page_starts_past_the_last_row_shown_even_once_earlier_rows_go() {
        let mut store = store();
        run_of(&store, "r1", ACCOUNT, &["a", "b", "c", "undated"]);
        for id in ["a", "b", "c", "undated"] {
            fail(&mut store, "r1", id, FileFailure::Unavailable);
        }
        store.conn.execute("UPDATE items SET created_at = NULL WHERE platform_id = 'undated'", []).unwrap();
        let page = |store: &Store, after: Option<&str>| -> Vec<String> {
            let cursor = after.map(|id| UnsavedCursor {
                created_at_secs: (id != "undated").then_some(100),
                platform_id: id.into(),
            });
            let items = store.unsaved_items("r1", cursor.as_ref(), 2).unwrap();
            items.into_iter().map(|item| item.platform_id).collect()
        };
        assert_eq!(page(&store, None), ["a", "b"]);

        store.retry_unsaved_files("r1", "r2", 20).unwrap();
        store.record_outcomes("r2", &[("a".into(), Outcome::Deleted)]).unwrap();

        assert_eq!(page(&store, Some("b")), ["c", "undated"]);
        assert!(page(&store, Some("undated")).is_empty());
    }

    #[test]
    fn a_retry_takes_each_item_with_everything_the_backup_needs() {
        let mut store = store();
        run_of(&store, "r1", ACCOUNT, &["a"]);
        fail(&mut store, "r1", "a", FileFailure::Unavailable);

        let retry = store.retry_unsaved_files("r1", "r2", 20).unwrap();

        assert_eq!(
            retry,
            FileRetryRun { platform: "bluesky".into(), account: ACCOUNT.into(), items: 1 }
        );
        let items = store.claim_pending_items("r2", 10).unwrap();
        assert_eq!(items[0].item_ref.token.as_deref(), Some("token-a"));
        assert_eq!(items[0].text.as_deref(), Some("text of a"));
        assert_eq!(items[0].media[0].file_name.as_deref(), Some("photo.jpg"));
        assert_eq!(items[0].platform_record.as_ref().unwrap().as_json(), "{\"id\":\"a\"}");
        assert_eq!(items[0].backup_gap.as_deref(), Some("poll votes are missing"));
    }

    #[test]
    fn an_item_stays_listed_until_a_later_run_gets_to_it() {
        let mut store = store();
        run_of(&store, "r1", ACCOUNT, &["a", "b"]);
        fail(&mut store, "r1", "a", FileFailure::Unavailable);
        fail(&mut store, "r1", "b", FileFailure::Unavailable);

        store.retry_unsaved_files("r1", "r2", 20).unwrap();
        assert_eq!(listed(&store, "r1"), ["a", "b"], "a retry that never ran loses nothing");

        store.record_outcomes("r2", &[("a".into(), Outcome::Deleted)]).unwrap();
        assert_eq!(listed(&store, "r1"), ["b"]);

        fail(&mut store, "r2", "b", FileFailure::Unreachable);
        assert!(listed(&store, "r1").is_empty());
        assert_eq!(listed(&store, "r2"), ["b"], "the newest run that tried it holds it now");
    }

    #[test]
    fn a_discarded_retry_leaves_no_copy_behind() {
        let mut store = store();
        run_of(&store, "r1", ACCOUNT, &["a"]);
        fail(&mut store, "r1", "a", FileFailure::Unavailable);
        store.retry_unsaved_files("r1", "r2", 20).unwrap();

        store.discard_retry("r2").unwrap();

        assert!(store.claim_pending_items("r2", 10).unwrap().is_empty());
        assert_eq!(listed(&store, "r1"), ["a"]);
    }

    #[test]
    fn another_account_does_not_settle_an_item() {
        let mut store = store();
        run_of(&store, "r1", ACCOUNT, &["a"]);
        fail(&mut store, "r1", "a", FileFailure::Unavailable);
        run_of(&store, "other", "someone-else", &["a"]);

        store.record_outcomes("other", &[("a".into(), Outcome::Deleted)]).unwrap();

        assert_eq!(listed(&store, "r1"), ["a"]);
    }

    #[test]
    fn once_a_later_run_settles_an_item_the_earlier_run_keeps_no_copy_of_it() {
        let mut store = store();
        run_of(&store, "r1", ACCOUNT, &["a"]);
        fail(&mut store, "r1", "a", FileFailure::Unavailable);
        let rows_in_r1 = |store: &Store| -> i64 {
            store
                .conn
                .query_row("SELECT COUNT(*) FROM items WHERE run_id = 'r1'", [], |r| r.get(0))
                .unwrap()
        };
        assert_eq!(rows_in_r1(&store), 1);

        store.retry_unsaved_files("r1", "r2", 20).unwrap();
        store.record_outcomes("r2", &[("a".into(), Outcome::Deleted)]).unwrap();

        assert_eq!(rows_in_r1(&store), 0);
    }
}

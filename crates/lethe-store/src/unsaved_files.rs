//! Items that stayed on the platform because their file could not be saved, and
//! the follow-up run that tries them again. Such a row keeps its platform record
//! until a later run settles the item, because the backup still needs it.

use rusqlite::{params, Connection};

use crate::state::{FileFailure, ItemState, RunState};
use crate::{Result, Store};

/// The rows of run `?1` still waiting on a file. A later run of the same account
/// settles a row by getting to the same item, whatever the outcome.
const STILL_UNSAVED: &str = "items.run_id = ?1 AND items.state = 'failed' AND items.file_failure IS NOT NULL
     AND NOT EXISTS (
        SELECT 1 FROM runs this
        JOIN runs later ON later.rowid > this.rowid
            AND later.platform = this.platform AND later.account = this.account
        JOIN items settled ON settled.run_id = later.run_id AND settled.platform_id = items.platform_id
        WHERE this.run_id = items.run_id AND settled.state IN ('deleted', 'skipped', 'failed')
     )";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsavedItem {
    pub platform_id: String,
    pub created_at_secs: Option<i64>,
    pub text: Option<String>,
    pub failure: FileFailure,
}

/// What stayed in a run because of its files: the counts, and the first rows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnsavedFiles {
    pub total: u64,
    /// How many of them may go without the file, with the person's consent.
    pub unavailable: u64,
    pub items: Vec<UnsavedItem>,
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
                forget_earlier_records(&tx, run_id, platform_id)?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn unsaved_files(&self, run_id: &str, limit: u32) -> Result<UnsavedFiles> {
        let (total, unavailable) = self.conn.query_row(
            &format!(
                "SELECT COUNT(*), COALESCE(SUM(items.file_failure = 'unavailable'), 0)
                 FROM items WHERE {STILL_UNSAVED}"
            ),
            params![run_id],
            |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64)),
        )?;
        let mut stmt = self.conn.prepare(&format!(
            "SELECT platform_id, created_at, text, file_failure FROM items
             WHERE {STILL_UNSAVED} ORDER BY created_at DESC, platform_id LIMIT ?2"
        ))?;
        let items = stmt
            .query_map(params![run_id, limit], |r| {
                Ok(UnsavedItem {
                    platform_id: r.get(0)?,
                    created_at_secs: r.get(1)?,
                    text: r.get(2)?,
                    failure: FileFailure::from_stored(&r.get::<_, String>(3)?),
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(UnsavedFiles { total, unavailable, items })
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
                                    platform_record, backup_gap, delete_reach, state)
                 SELECT ?2, platform_id, content_type, created_at, token, text, media_json,
                        platform_record, backup_gap, delete_reach, ?3 FROM items WHERE {STILL_UNSAVED}"
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

/// Earlier runs that still hold this item no longer need its platform record once
/// a later run has dealt with the item, and the record can hold contacts and locations.
pub(crate) fn forget_earlier_records(conn: &Connection, run_id: &str, platform_id: &str) -> Result<()> {
    conn.prepare_cached(
        "UPDATE items SET platform_record = NULL
         WHERE platform_id = ?2 AND file_failure IS NOT NULL AND run_id IN (
            SELECT earlier.run_id FROM runs this
            JOIN runs earlier ON earlier.rowid < this.rowid
                AND earlier.platform = this.platform AND earlier.account = this.account
            WHERE this.run_id = ?1
         )",
    )?
    .execute(params![run_id, platform_id])?;
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
                delete_reach: Default::default(),
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
        let unsaved = store.unsaved_files(run_id, 50).unwrap();
        unsaved.items.into_iter().map(|item| item.platform_id).collect()
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

        let unsaved = store.unsaved_files("r1", 50).unwrap();

        assert_eq!((unsaved.total, unsaved.unavailable), (2, 1));
        assert_eq!(unsaved.items[0].platform_id, "file");
        assert_eq!(unsaved.items[0].failure, FileFailure::Unavailable);
        assert_eq!(unsaved.items[0].text.as_deref(), Some("text of file"));
        assert_eq!(unsaved.items[1].failure, FileFailure::Unreachable);
    }

    #[test]
    fn the_list_counts_every_row_past_its_limit() {
        let mut store = store();
        run_of(&store, "r1", ACCOUNT, &["a", "b", "c"]);
        for id in ["a", "b", "c"] {
            fail(&mut store, "r1", id, FileFailure::Unavailable);
        }

        let unsaved = store.unsaved_files("r1", 2).unwrap();

        assert_eq!(unsaved.total, 3);
        assert_eq!(unsaved.items.len(), 2);
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
    fn once_a_later_run_settles_an_item_its_platform_record_is_gone_from_the_earlier_run() {
        let mut store = store();
        run_of(&store, "r1", ACCOUNT, &["a"]);
        fail(&mut store, "r1", "a", FileFailure::Unavailable);
        let record_of = |store: &Store| -> Option<String> {
            store
                .conn
                .query_row(
                    "SELECT platform_record FROM items WHERE run_id = 'r1' AND platform_id = 'a'",
                    [],
                    |r| r.get(0),
                )
                .unwrap()
        };
        assert!(record_of(&store).is_some());

        store.retry_unsaved_files("r1", "r2", 20).unwrap();
        store.record_outcomes("r2", &[("a".into(), Outcome::Deleted)]).unwrap();

        assert_eq!(record_of(&store), None);
    }
}

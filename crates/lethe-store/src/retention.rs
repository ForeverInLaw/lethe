//! What the store keeps of a run once it no longer needs it. A run that has its
//! receipt keeps only the items still waiting on a file.

use rusqlite::{params, Connection};

use crate::unsaved_files::{self, WAITS_ON_A_FILE};
use crate::{Result, Store};

impl Store {
    /// Forgets what no run can use any more. Call it only while no run is previewed
    /// or under way, such as when the app starts. A run that never began deleting
    /// goes whole: its preview can no longer be started. A run without a receipt
    /// keeps the count of what it deleted and its items still waiting on a file.
    pub fn forget_stale_runs(&self) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM runs WHERE state IN ('enumerating', 'preview')",
            [],
        )?;
        tx.execute(
            &format!("DELETE FROM items WHERE state != 'deleted' AND NOT ({WAITS_ON_A_FILE})"),
            [],
        )?;
        tx.commit()?;
        Ok(())
    }
}

/// Drops what older versions kept and this one forgets as it goes. Safe at any
/// time, so it runs whenever the store opens.
pub(crate) fn forget_what_older_versions_kept(conn: &Connection) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    // Before the receipts drop their rows: a later run's rows tell which copies are done.
    unsaved_files::drop_copies_older_versions_kept(&tx)?;
    drop_receipted_rows(&tx, None)?;
    tx.execute(
        &format!(
            "UPDATE items SET text = NULL, media_json = '[]', platform_record = NULL
             WHERE state IN ('deleted', 'skipped', 'failed') AND NOT ({WAITS_ON_A_FILE})"
        ),
        [],
    )?;
    tx.commit()?;
    Ok(())
}

/// Drops what runs with a receipt no longer need: every item but those still
/// waiting on a file. `None` covers every such run.
pub(crate) fn drop_receipted_rows(conn: &Connection, run_id: Option<&str>) -> Result<()> {
    conn.execute(
        &format!(
            "DELETE FROM items
             WHERE run_id IN (SELECT run_id FROM receipts WHERE ?1 IS NULL OR run_id = ?1)
               AND NOT ({WAITS_ON_A_FILE})"
        ),
        params![run_id],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{FileFailure, ItemSnapshot, ItemState, NewRun, RunState, Store};
    use lethe_adapter::{ContentType, DeleteReach, ItemRef, Outcome};

    fn item(id: &str, state: ItemState) -> ItemSnapshot {
        ItemSnapshot {
            item_ref: ItemRef {
                platform_id: id.into(),
                token: None,
            },
            content_type: ContentType::Post,
            subtype: None,
            created_at_secs: Some(1),
            text: Some(format!("text of {id}")),
            media: Vec::new(),
            platform_record: None,
            backup_gap: None,
            delete_reach: DeleteReach::Everyone,
            scope_id: None,
            state,
        }
    }

    fn new_run(store: &Store, run_id: &str, state: RunState) {
        store
            .create_run(&NewRun {
                run_id: run_id.into(),
                platform: "bluesky".into(),
                account: "acc".into(),
                filter_json: "{}".into(),
                started_secs: 0,
            })
            .unwrap();
        store.set_run_state(run_id, state).unwrap();
    }

    /// Run `run_id`, stopped with one item per way an item ends up: deleted, kept,
    /// stayed for want of a file, and not reached.
    fn run_with_every_outcome(store: &mut Store, run_id: &str) {
        new_run(store, run_id, RunState::Executing);
        store
            .snapshot_items(
                run_id,
                &[
                    item("gone", ItemState::Pending),
                    item("kept", ItemState::Protected),
                    item("photo", ItemState::Pending),
                    item("left", ItemState::Pending),
                ],
            )
            .unwrap();
        store
            .record_outcomes(run_id, &[("gone".into(), Outcome::Deleted)])
            .unwrap();
        store
            .record_file_failures(
                run_id,
                &[("photo".into(), FileFailure::Unavailable, "refused".into())],
            )
            .unwrap();
    }

    fn rows_of(store: &Store, run_id: &str) -> Vec<String> {
        let mut stmt = store
            .conn
            .prepare("SELECT platform_id FROM items WHERE run_id = ?1 ORDER BY platform_id")
            .unwrap();
        stmt.query_map([run_id], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    fn text_of(store: &Store, run_id: &str, platform_id: &str) -> Option<String> {
        store
            .conn
            .query_row(
                "SELECT text FROM items WHERE run_id = ?1 AND platform_id = ?2",
                [run_id, platform_id],
                |r| r.get(0),
            )
            .unwrap()
    }

    #[test]
    fn a_receipt_leaves_only_the_items_still_waiting_on_a_file() {
        let mut store = Store::open_in_memory("k").unwrap();
        run_with_every_outcome(&mut store, "r");

        store.save_receipt("r", "{}", "pub", "sig").unwrap();

        assert_eq!(rows_of(&store, "r"), ["photo"]);
        assert_eq!(
            text_of(&store, "r", "photo").as_deref(),
            Some("text of photo"),
            "a retry still needs it"
        );
    }

    #[test]
    fn a_preview_that_never_ran_is_forgotten_whole() {
        let store = Store::open_in_memory("k").unwrap();
        new_run(&store, "previewed", RunState::Enumerating);
        store
            .snapshot_items("previewed", &[item("a", ItemState::Pending)])
            .unwrap();
        new_run(&store, "retry", RunState::Preview);

        store.forget_stale_runs().unwrap();

        let runs: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM runs", [], |r| r.get(0))
            .unwrap();
        assert_eq!(runs, 0);
        assert!(rows_of(&store, "previewed").is_empty());
    }

    #[test]
    fn an_interrupted_run_keeps_only_the_count_of_what_it_deleted_and_what_waits_on_a_file() {
        let mut store = Store::open_in_memory("k").unwrap();
        run_with_every_outcome(&mut store, "r");

        store.forget_stale_runs().unwrap();

        assert_eq!(rows_of(&store, "r"), ["gone", "photo"]);
        assert_eq!(store.runs_without_receipt().unwrap()[0].deleted, 1);
        assert_eq!(
            text_of(&store, "r", "photo").as_deref(),
            Some("text of photo")
        );
    }

    #[test]
    fn what_an_older_version_left_behind_is_forgotten_when_the_store_opens() {
        let path = std::env::temp_dir().join(format!("lethe-retention-{}", std::process::id()));
        let path = path.to_str().unwrap();
        {
            let mut store = Store::open(path, "k").unwrap();
            run_with_every_outcome(&mut store, "first");
            run_with_every_outcome(&mut store, "second");
            // As an older version left them: text kept after the delete, a receipt that
            // dropped nothing, and the first run's copy of an item the second one got to.
            store
                .conn
                .execute_batch(
                    "UPDATE items SET text = 'still here' WHERE run_id = 'first' AND platform_id = 'gone';
                     INSERT INTO receipts (run_id, summary_json, public_key_hex, signature_hex)
                     VALUES ('second', '{}', 'pub', 'sig');
                     INSERT INTO items (run_id, platform_id, content_type, state, file_failure)
                     VALUES ('first', 'photo', 'post', 'failed', 'unavailable');",
                )
                .unwrap();
        }

        let store = Store::open(path, "k").unwrap();
        let (first, second) = (rows_of(&store, "first"), rows_of(&store, "second"));
        let gone = text_of(&store, "first", "gone");
        std::fs::remove_file(path).unwrap();

        assert_eq!(
            first,
            ["gone", "kept", "left"],
            "the second run holds the photo now"
        );
        assert_eq!(gone, None);
        assert_eq!(second, ["photo"]);
    }
}

//! What a run does with items it cannot delete for everyone.

use std::sync::Arc;

use lethe_adapter::{AdapterError, DeleteReach, EnumeratePlan, Item};
use lethe_store::{NewRun, PendingConsents, Store};

use super::tests::{
    downloaded, match_all_filter, media_item, run_media, run_media_allowing_only_for_self,
    MediaAdapter,
};
use super::{execute, snapshot, RunOutcome, RunRequest};
use crate::scheduler::Scheduler;
use crate::RunControl;

fn item(id: &str, reach: DeleteReach) -> Item {
    Item { delete_reach: reach, ..media_item(id, &[]) }
}

fn mixed_chat() -> Vec<Item> {
    vec![
        item("for-everyone", DeleteReach::Everyone),
        item("only-mine", DeleteReach::OnlyForSelf),
        item("service-note", DeleteReach::Nowhere),
    ]
}

fn no_files(items: Vec<Item>) -> Arc<MediaAdapter> {
    Arc::new(MediaAdapter::new(items, |_, _| Ok(downloaded(b""))))
}

#[tokio::test]
async fn without_consent_only_what_goes_for_everyone_is_deleted() {
    let adapter = no_files(mixed_chat());

    let run = run_media(adapter.clone(), RunControl::new()).await;

    assert_eq!(
        run.outcome.as_ref().unwrap(),
        &RunOutcome { deleted: 1, kept_only_for_self: 1, undeletable: 1, ..Default::default() }
    );
    assert_eq!(adapter.journal(), ["delete for-everyone"]);
    let counts = run.store.preview_counts("media").unwrap();
    assert_eq!((counts.protected, counts.undeletable), (1, 1));
}

#[tokio::test]
async fn with_consent_it_also_goes_for_this_account_and_is_counted_apart() {
    let adapter = no_files(mixed_chat());

    let run = run_media_allowing_only_for_self(adapter.clone()).await;

    assert_eq!(
        run.outcome.as_ref().unwrap(),
        &RunOutcome { deleted: 2, deleted_only_for_self: 1, undeletable: 1, ..Default::default() }
    );
    assert_eq!(adapter.journal(), ["delete for-everyone", "delete only-mine"]);
}

#[tokio::test]
async fn a_run_without_a_receipt_still_tells_what_others_can_see() {
    let run = run_media_allowing_only_for_self(no_files(mixed_chat())).await;

    let runs = run.store.runs_without_receipt().unwrap();

    assert_eq!((runs[0].deleted, runs[0].deleted_only_for_self), (2, 1));
}

/// The request behind `previewed`: no consent given.
fn preview_request() -> RunRequest {
    RunRequest {
        run_id: "preview".into(),
        platform: "fake".into(),
        account_id: "fake:a".into(),
        account_label: "acc".into(),
        plan: EnumeratePlan::default(),
        filter: match_all_filter(),
        allow_incomplete_backup: false,
        allow_lost_files: false,
        allow_only_for_self: false,
    }
}

/// A run stopped at the preview, where the person can still change what goes.
async fn previewed(items: Vec<Item>) -> Store {
    let store = Store::open_in_memory("test-key").unwrap();
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let req = preview_request();
    store
        .create_run(&NewRun {
            run_id: req.run_id.clone(),
            platform: req.platform.clone(),
            account: req.account_label.clone(),
            filter_json: "{}".into(),
            started_secs: 0,
        })
        .unwrap();
    snapshot(no_files(items), &store, &req, &tx).await.unwrap();
    store
}

#[tokio::test]
async fn what_the_platform_will_not_delete_cannot_be_chosen_in_the_preview() {
    let store = previewed(mixed_chat()).await;

    assert!(!store.set_item_protected("preview", "service-note", false).unwrap());
    assert!(!store.set_item_protected("preview", "service-note", true).unwrap());
    let counts = store.preview_counts("preview").unwrap();
    assert_eq!((counts.pending, counts.undeletable), (2, 1));
}

#[tokio::test]
async fn the_preview_counts_each_consent_and_their_overlap() {
    let gap_and_mine = Item {
        backup_gap: Some("no file".into()),
        ..item("both", DeleteReach::OnlyForSelf)
    };
    let gap = Item { backup_gap: Some("no file".into()), ..item("gap", DeleteReach::Everyone) };

    let store = previewed(vec![gap_and_mine, gap, item("mine", DeleteReach::OnlyForSelf)]).await;

    assert_eq!(
        store.pending_consents("preview").unwrap(),
        PendingConsents { backup_gaps: 2, only_for_self: 2, both: 1 }
    );
}

#[tokio::test]
async fn a_retry_still_knows_the_item_goes_only_for_this_account() {
    let stuck = Item {
        delete_reach: DeleteReach::OnlyForSelf,
        ..media_item("mine", &[("photo", 3)])
    };
    let adapter = Arc::new(MediaAdapter::new(vec![stuck], |_, _| {
        Err(AdapterError::FileRefused("no longer there".into()))
    }));
    let run = run_media_allowing_only_for_self(adapter).await;

    run.store.retry_unsaved_files("media", "retry", 1).unwrap();

    let claimed = run.store.claim_pending_items("retry", 10).unwrap();
    assert_eq!(claimed[0].delete_reach, DeleteReach::OnlyForSelf);
}

#[tokio::test]
async fn a_run_resumed_after_a_stop_still_counts_what_it_kept() {
    let mut store = previewed(mixed_chat()).await;
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let (adapter, req) = (no_files(mixed_chat()), preview_request());
    let stopped = RunControl::new();
    stopped.stop();
    let first = execute(adapter.clone(), &mut store, &mut Scheduler::new(), &req, stopped, &tx, None).await;
    assert!(first.is_err(), "stopped right after the protections");

    let resumed =
        execute(adapter, &mut store, &mut Scheduler::new(), &req, RunControl::new(), &tx, None).await.unwrap();

    assert_eq!(
        resumed,
        RunOutcome { deleted: 1, kept_only_for_self: 1, undeletable: 1, ..Default::default() }
    );
}

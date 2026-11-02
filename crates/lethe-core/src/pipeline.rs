//! Two-phase run. `snapshot` (Phase 1) builds the immutable preview; `execute`
//! (Phase 2) acts on exactly the rows still `pending`. dry-run == executed is
//! structural: the preview IS the snapshot the executor reads.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use lethe_adapter::{AdapterError, EnumeratePlan, FetchedMedia, Item, MediaRef, Outcome, PlatformAdapter};
use lethe_crypto::receipt::{ReceiptSigner, RunSummary, SignedReceipt};
use lethe_crypto::DataKey;
use lethe_store::{FileFailure, ItemSnapshot, ItemState, PendingItem, PreviewCounts, RunState, Store};

use crate::archive::ArchiveWriter;
use crate::filter::{FilterSpec, Predicate};
use crate::scheduler::Scheduler;
use crate::{EngineError, ProgressEvent, ProgressTx, Result, RunControl};

const SNAPSHOT_FLUSH: usize = 500;
const DELETE_BATCH: usize = 100;
/// How long a file gets to come back from a network problem, one wait per retry.
const FETCH_RETRY_DELAYS: [Duration; 3] =
    [Duration::from_secs(2), Duration::from_secs(8), Duration::from_secs(30)];
const STOP_POLL: Duration = Duration::from_millis(200);

pub struct RunRequest {
    pub run_id: String,
    pub platform: String,
    pub account_id: String,
    pub account_label: String,
    pub plan: EnumeratePlan,
    pub filter: FilterSpec,
    pub backup: bool,
    /// The person agreed to delete items the backup cannot hold in full. Without
    /// this, such items stay on the platform.
    pub allow_incomplete_backup: bool,
    /// The person agreed to delete items whose files the platform refuses to hand
    /// over. Any other download error keeps its item regardless.
    pub allow_lost_files: bool,
}

/// Where the encrypted backup is written + the data-key that seals it. The
/// engine stays vault-agnostic: the app derives the key (Argon2 passphrase or
/// OS keychain) and chooses the path, then hands both in.
pub struct BackupTarget {
    pub path: PathBuf,
    pub key: DataKey,
}

/// Final tally of a Phase-2 run. The caller (which owns the clock + identity)
/// turns this into a `RunSummary` and signs the receipt.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunOutcome {
    pub deleted: u64,
    pub skipped: u64,
    pub failed: u64,
}

/// Sign the run summary and persist the receipt. Shared by the CLI and the
/// Tauri shell so receipt handling lives in exactly one place.
pub fn store_receipt(
    store: &Store,
    signer: &ReceiptSigner,
    summary: &RunSummary,
) -> Result<SignedReceipt> {
    let receipt = signer.sign(summary)?;
    let summary_json =
        serde_json::to_string(&receipt.summary).map_err(|e| EngineError::Io(e.to_string()))?;
    store.save_receipt(
        &summary.run_id,
        &summary_json,
        &receipt.public_key_hex,
        &receipt.signature_hex,
    )?;
    Ok(receipt)
}

/// Phase 1: enumerate → immutable snapshot. Returns the preview counts. New
/// content created after this point is simply not in the set (correct).
pub async fn snapshot(
    adapter: Arc<dyn PlatformAdapter>,
    store: &Store,
    req: &RunRequest,
    progress: &ProgressTx,
) -> Result<PreviewCounts> {
    let predicate: Predicate = req.filter.clone().compile()?;

    let mut stream = adapter
        .enumerate(&req.plan)
        .await
        .map_err(|e| EngineError::Adapter(e.to_string()))?;

    let mut buf: Vec<ItemSnapshot> = Vec::with_capacity(SNAPSHOT_FLUSH);
    let mut seen: u64 = 0;

    while let Some(item) = stream.next().await {
        let item: Item = item.map_err(|e| EngineError::Adapter(e.to_string()))?;
        seen += 1;

        let pid = &item.item_ref.platform_id;
        let state = if predicate.is_protected(pid) {
            Some(ItemState::Protected)
        } else if predicate.matches(&item) {
            Some(ItemState::Pending)
        } else {
            None // not in the set
        };

        if let Some(state) = state {
            buf.push(ItemSnapshot {
                item_ref: item.item_ref.clone(),
                content_type: item.content_type,
                created_at_secs: item.created_at.map(|t| t.unix_timestamp()),
                text: item.text.clone(),
                media: item.media.clone(),
                platform_record: item.platform_record.clone(),
                backup_gap: item.backup_gap.clone(),
                state,
            });
        }

        if buf.len() >= SNAPSHOT_FLUSH {
            store.snapshot_items(&req.run_id, &buf)?;
            buf.clear();
        }
        if seen % 100 == 0 {
            let _ = progress.send(ProgressEvent::Enumerating { seen });
        }
    }
    if !buf.is_empty() {
        store.snapshot_items(&req.run_id, &buf)?;
    }

    let counts = store.preview_counts(&req.run_id)?;
    let _ = progress.send(ProgressEvent::PreviewReady {
        pending: counts.pending,
        protected: counts.protected,
    });
    Ok(counts)
}

/// Phase 2: backup → delete → checkpoint, over the `pending` rows only.
/// Idempotent + resumable: re-running skips rows already in a terminal state.
pub async fn execute(
    adapter: Arc<dyn PlatformAdapter>,
    store: &mut Store,
    scheduler: &mut Scheduler,
    req: &RunRequest,
    control: RunControl,
    progress: &ProgressTx,
    backup: Option<BackupTarget>,
) -> Result<RunOutcome> {
    let policy = adapter.rate_policy();
    let mut outcome = RunOutcome::default();

    // Open the encrypted backup up front (FR-BAK-1, on-by-default): if a target
    // is given and the run requests backup, every item is archived BEFORE its
    // delete, so an interrupted run never deletes anything it has not backed up.
    let mut writer = match (&backup, req.backup) {
        (Some(target), true) => Some(ArchiveWriter::create(target, req)?),
        _ => None,
    };
    if !req.allow_incomplete_backup {
        store.protect_backup_gaps(&req.run_id)?;
    }

    // From here on the preview is final: `set_item_protected` refuses, and every
    // protection committed before this line is seen by the first claim.
    store.set_run_state(&req.run_id, RunState::Executing)?;
    let total = store.preview_counts(&req.run_id)?.pending;
    let _ = progress.send(ProgressEvent::Deleting { deleted: 0, skipped: 0, failed: 0, total });

    let media_total_bytes = store.pending_media(&req.run_id)?.bytes;
    let mut media_done_bytes = 0;
    // A rate-limited delete comes back in the next claim; its backup is already done.
    let mut archived: HashSet<String> = HashSet::new();

    loop {
        if !keep_running(&control).await {
            return abort(writer);
        }

        let batch = store.claim_pending_items(&req.run_id, DELETE_BATCH)?;
        if batch.is_empty() {
            break;
        }

        let mut deletable = Vec::with_capacity(batch.len());
        let mut records = Vec::new();
        let mut retry_after_secs: Option<u64> = None;

        for item in &batch {
            let platform_id = &item.item_ref.platform_id;
            let Some(w) = writer.as_mut().filter(|_| !archived.contains(platform_id)) else {
                deletable.push(item);
                continue;
            };

            match archive_item(adapter.as_ref(), w, item, req.allow_lost_files, &control).await? {
                ArchiveResult::Stopped => return abort(writer),
                ArchiveResult::Archived => {
                    archived.insert(platform_id.clone());
                    deletable.push(item);
                    if !item.media.is_empty() {
                        media_done_bytes += item.media.iter().filter_map(|media| media.size).sum::<u64>();
                        let _ = progress.send(ProgressEvent::Archiving {
                            done_bytes: media_done_bytes,
                            total_bytes: media_total_bytes,
                        });
                    }
                }
                // Not archived, so not deleted: the item stays pending for the next claim.
                ArchiveResult::FetchFailed(AdapterError::RateLimited { retry_after_secs: secs }) => {
                    retry_after_secs = retry_after_secs.max(Some(secs));
                }
                ArchiveResult::FetchFailed(AdapterError::NotFound) => {
                    outcome.skipped += 1;
                    let reason = "already deleted".to_string();
                    records.push((platform_id.clone(), Outcome::Skipped { reason }));
                }
                ArchiveResult::FetchFailed(error) => {
                    outcome.failed += 1;
                    let failure = match error {
                        AdapterError::FileRefused(_) => FileFailure::Unavailable,
                        _ => FileFailure::Unreachable,
                    };
                    let reason = format!("not backed up, so not deleted: {error}");
                    // Right away: a stop later in this batch must not lose it from the list.
                    store.record_file_failures(&req.run_id, &[(platform_id.clone(), failure, reason)])?;
                    let _ = progress.send(ProgressEvent::Deleting {
                        deleted: outcome.deleted,
                        skipped: outcome.skipped,
                        failed: outcome.failed,
                        total,
                    });
                }
            }
        }

        if !deletable.is_empty() {
            // Downloads can take long enough for a stop to arrive after the last gate.
            if !keep_running(&control).await {
                return abort(writer);
            }
            if let Some(w) = writer.as_ref() {
                w.sync()?;
            }

            // Rate gate (one token per delete call; adapter batches internally).
            scheduler.bucket(&req.account_id, &policy).acquire().await;

            let delete_refs: Vec<_> = deletable.iter().map(|item| item.item_ref.clone()).collect();
            let outcomes = adapter.delete(&delete_refs).await;

            // Terminal outcomes are checkpointed. Rate-limited items stay pending
            // and are retried after the scheduler applies the platform delay.
            for (item, result) in deletable.iter().zip(outcomes) {
                match &result {
                    Outcome::Deleted => outcome.deleted += 1,
                    Outcome::Skipped { .. } => outcome.skipped += 1,
                    Outcome::Failed { .. } => outcome.failed += 1,
                    Outcome::RateLimited { retry_after_secs: secs } => {
                        retry_after_secs = retry_after_secs.max(Some(*secs));
                        continue;
                    }
                }
                records.push((item.item_ref.platform_id.clone(), result));
            }
        }
        if !records.is_empty() {
            store.record_outcomes(&req.run_id, &records)?;
        }

        let _ = progress.send(ProgressEvent::Deleting {
            deleted: outcome.deleted,
            skipped: outcome.skipped,
            failed: outcome.failed,
            total,
        });

        if let Some(wait_secs) = retry_after_secs {
            let bucket = scheduler.bucket(&req.account_id, &policy);
            let rate_per_sec = bucket.rate_per_sec();
            let _ = progress.send(ProgressEvent::Throttled { rate_per_sec, wait_secs });
            bucket.penalize(Duration::from_secs(wait_secs)).await;
        }
    }

    // Seal the archive (emits the FINAL frame; truncation is now detectable).
    if let Some(w) = writer.take() {
        w.finish()?;
    }

    // Receipt signing is the caller's job (it owns the clock + identity): it
    // builds a `RunSummary` from this `RunOutcome` and calls `store_receipt`.
    let _ = progress.send(ProgressEvent::Done { run_id: req.run_id.clone() });
    Ok(outcome)
}

/// Waits out a pause. False once the run has been stopped.
async fn keep_running(control: &RunControl) -> bool {
    while control.is_paused() && !control.is_stopped() {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    !control.is_stopped()
}

/// Seals what was archived so far: a stopped run keeps a complete backup of
/// everything it already deleted.
fn abort(writer: Option<ArchiveWriter>) -> Result<RunOutcome> {
    if let Some(writer) = writer {
        writer.finish()?;
    }
    Err(EngineError::Aborted)
}

enum ArchiveResult {
    Archived,
    /// The run was stopped before all of the item's files were fetched.
    Stopped,
    FetchFailed(AdapterError),
}

/// Downloads one file, waiting out a network problem so that a blip does not cost
/// the item its backup. `None` once the run has been stopped.
async fn fetch_file(
    adapter: &dyn PlatformAdapter,
    item: &PendingItem,
    media: &MediaRef,
    control: &RunControl,
) -> Option<std::result::Result<FetchedMedia, AdapterError>> {
    let mut delays = FETCH_RETRY_DELAYS.iter();
    loop {
        if !keep_running(control).await {
            return None;
        }
        let result = adapter.fetch_media(&item.item_ref, media).await;
        match (&result, delays.next()) {
            (Err(AdapterError::Transport(_)), Some(delay)) => {
                if !wait(*delay, control).await {
                    return None;
                }
            }
            _ => return Some(result),
        }
    }
}

/// Sleeps in short steps, so a stop does not have to sit through the whole delay.
/// False once the run has been stopped.
async fn wait(delay: Duration, control: &RunControl) -> bool {
    let until = tokio::time::Instant::now() + delay;
    while tokio::time::Instant::now() < until {
        if control.is_stopped() {
            return false;
        }
        tokio::time::sleep_until(until.min(tokio::time::Instant::now() + STOP_POLL)).await;
    }
    true
}

/// Downloads an item's files and archives them with its record. Unless the result
/// is `Archived`, nothing was written and the item must not be deleted. With
/// `allow_lost_files`, a file the platform refuses leaves a hole in the record instead. An
/// error means the archive itself failed and the run must end.
async fn archive_item(
    adapter: &dyn PlatformAdapter,
    writer: &mut ArchiveWriter,
    item: &PendingItem,
    allow_lost_files: bool,
    control: &RunControl,
) -> Result<ArchiveResult> {
    let mut files = Vec::with_capacity(item.media.len());
    let mut lost_reasons = Vec::new();
    let mut result = ArchiveResult::Archived;
    for media in &item.media {
        match fetch_file(adapter, item, media, control).await {
            None => {
                result = ArchiveResult::Stopped;
                break;
            }
            Some(Ok(file)) => files.push(Some(file)),
            Some(Err(error @ AdapterError::FileRefused(_))) if allow_lost_files => {
                files.push(None);
                lost_reasons.push(error.to_string());
            }
            Some(Err(error)) => {
                result = ArchiveResult::FetchFailed(error);
                break;
            }
        }
    }

    let written = match result {
        ArchiveResult::Archived => writer.write_item(item, &files, &lost_reasons),
        _ => Ok(()),
    };
    for file in files.iter().flatten() {
        if let Err(error) = adapter.release_media(file).await {
            tracing::warn!(%error, "could not remove a downloaded media file");
        }
    }
    written?;
    Ok(result)
}

#[cfg(test)]
mod file_failure_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use futures::stream;
    use lethe_adapter::{
        AdapterError, Capabilities, ContentType, Descriptor, Engagement, ItemRef, ItemStream, PlatformRecord,
        RatePolicy, RiskClass,
    };
    use crate::archive::audit_archive;
    use lethe_crypto::container::ContainerReader;
    use std::fs::File;
    use std::sync::Mutex;
    use lethe_crypto::receipt::{verify, ReceiptSigner, RunSummary};
    use lethe_store::{ItemQuery, NewRun, Store};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Adapter that enumerates N posts and reports every delete as success.
    struct FakeAdapter {
        descriptor: Descriptor,
        n: usize,
    }

    impl FakeAdapter {
        fn with_items(n: usize) -> Self {
            let descriptor = Descriptor {
                id: "fake",
                display_name: "Fake",
                risk_class: RiskClass::Green,
                content_types: &[ContentType::Post],
                pushdown: &[],
                capabilities: Capabilities {
                    can_redact: false,
                    can_undo: false,
                    batch_delete_max: 100,
                },
                endpoints: vec![],
            };
            Self { descriptor, n }
        }
    }

    #[async_trait]
    impl PlatformAdapter for FakeAdapter {
        fn descriptor(&self) -> &Descriptor {
            &self.descriptor
        }

        async fn enumerate(&self, _plan: &EnumeratePlan) -> std::result::Result<ItemStream, AdapterError> {
            let items: Vec<_> = (0..self.n)
                .map(|i| {
                    Ok(Item {
                        content_type: ContentType::Post,
                        created_at: None,
                        text: Some(format!("post {i}")),
                        engagement: Engagement::default(),
                        scope_id: None,
                        media: vec![],
                        platform_record: None,
                        backup_gap: None,
                        item_ref: ItemRef {
                            platform_id: format!("at://fake/app.bsky.feed.post/{i}"),
                            token: Some(format!("app.bsky.feed.post:{i}")),
                        },
                    })
                })
                .collect();
            Ok(Box::pin(stream::iter(items)))
        }

        async fn delete(&self, items: &[ItemRef]) -> Vec<Outcome> {
            items.iter().map(|_| Outcome::Deleted).collect()
        }

        fn rate_policy(&self) -> RatePolicy {
            RatePolicy { max_per_sec: 1000.0, max_per_min: None, burst: 1000 }
        }
    }

    struct RateLimitOnceAdapter {
        inner: FakeAdapter,
        calls: AtomicUsize,
    }

    impl RateLimitOnceAdapter {
        fn new() -> Self {
            Self {
                inner: FakeAdapter::with_items(1),
                calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl PlatformAdapter for RateLimitOnceAdapter {
        fn descriptor(&self) -> &Descriptor {
            self.inner.descriptor()
        }

        async fn enumerate(&self, plan: &EnumeratePlan) -> std::result::Result<ItemStream, AdapterError> {
            self.inner.enumerate(plan).await
        }

        async fn delete(&self, items: &[ItemRef]) -> Vec<Outcome> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                return items.iter().map(|_| Outcome::RateLimited { retry_after_secs: 0 }).collect();
            }
            items.iter().map(|_| Outcome::Deleted).collect()
        }

        fn rate_policy(&self) -> RatePolicy {
            self.inner.rate_policy()
        }
    }

    fn match_all_filter() -> FilterSpec {
        FilterSpec {
            content_types: Default::default(),
            date_from: None,
            date_to: None,
            keyword: None,
            engagement_max: None,
            allowlist_ids: Default::default(),
        }
    }

    #[tokio::test]
    async fn vertical_backs_up_then_deletes_then_receipt_verifies() {
        let n = 3;
        let adapter: Arc<dyn PlatformAdapter> = Arc::new(FakeAdapter::with_items(n));
        let mut store = Store::open_in_memory("test-key").unwrap();
        let mut scheduler = Scheduler::new();
        let control = RunControl::new();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();

        let req = RunRequest {
            run_id: "r1".into(),
            platform: "fake".into(),
            account_id: "fake:a".into(),
            account_label: "acc".into(),
            plan: EnumeratePlan::default(),
            filter: match_all_filter(),
            backup: true,
            allow_incomplete_backup: false,
            allow_lost_files: false,
        };
        store
            .create_run(&NewRun {
                run_id: req.run_id.clone(),
                platform: req.platform.clone(),
                account: req.account_label.clone(),
                filter_json: "{}".into(),
                started_secs: 0,
            })
            .unwrap();

        // Phase 1: every item matches -> all pending.
        let counts = snapshot(adapter.clone(), &store, &req, &tx).await.unwrap();
        assert_eq!(counts.pending, n as u64);

        // Phase 2: backup-then-delete.
        let path = std::env::temp_dir().join("lethe_pipeline_vertical_test.bin");
        let key: DataKey = [9u8; 32];
        let outcome = execute(
            adapter,
            &mut store,
            &mut scheduler,
            &req,
            control,
            &tx,
            Some(BackupTarget { path: path.clone(), key }),
        )
        .await
        .unwrap();
        assert_eq!(outcome, RunOutcome { deleted: n as u64, skipped: 0, failed: 0 });

        // The encrypted archive decrypts to manifest + one record per item.
        let file = File::open(&path).unwrap();
        let mut reader = ContainerReader::open(file, &key).unwrap();
        let mut chunks = 0;
        let mut first_item = None;
        while let Some(chunk) = reader.read_chunk().unwrap() {
            if first_item.is_none() && chunks == 1 {
                first_item = Some(chunk);
            }
            chunks += 1;
        }
        assert_eq!(chunks, n + 1, "manifest + one record per deleted item");
        let first_item: serde_json::Value = serde_json::from_slice(&first_item.unwrap()).unwrap();
        assert_eq!(first_item["text"], "post 0");
        std::fs::remove_file(&path).ok();

        // Re-running deletes nothing (idempotent: no rows left pending).
        let again = execute(
            Arc::new(FakeAdapter::with_items(n)),
            &mut store,
            &mut scheduler,
            &req,
            RunControl::new(),
            &tx,
            None,
        )
        .await
        .unwrap();
        assert_eq!(again, RunOutcome::default());

        // Receipt signs the counts and verifies offline.
        let signer = ReceiptSigner::generate();
        let summary = RunSummary {
            run_id: req.run_id.clone(),
            platform: req.platform.clone(),
            account_label: req.account_label.clone(),
            started_epoch_secs: 0,
            finished_epoch_secs: 1,
            deleted: outcome.deleted,
            skipped: outcome.skipped,
            failed: outcome.failed,
        };
        let receipt = store_receipt(&store, &signer, &summary).unwrap();
        assert!(verify(&receipt).is_ok());
    }

    #[tokio::test]
    async fn rate_limit_penalizes_without_checkpointing_as_failed() {
        let adapter: Arc<dyn PlatformAdapter> = Arc::new(RateLimitOnceAdapter::new());
        let mut store = Store::open_in_memory("test-key").unwrap();
        let mut scheduler = Scheduler::new();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        let req = RunRequest {
            run_id: "rl".into(),
            platform: "fake".into(),
            account_id: "fake:a".into(),
            account_label: "acc".into(),
            plan: EnumeratePlan::default(),
            filter: match_all_filter(),
            backup: false,
            allow_incomplete_backup: false,
            allow_lost_files: false,
        };
        store
            .create_run(&NewRun {
                run_id: req.run_id.clone(),
                platform: req.platform.clone(),
                account: req.account_label.clone(),
                filter_json: "{}".into(),
                started_secs: 0,
            })
            .unwrap();

        let counts = snapshot(adapter.clone(), &store, &req, &tx).await.unwrap();
        assert_eq!(counts.pending, 1);

        let outcome = execute(
            adapter,
            &mut store,
            &mut scheduler,
            &req,
            RunControl::new(),
            &tx,
            None,
        )
        .await
        .unwrap();

        assert_eq!(outcome, RunOutcome { deleted: 1, skipped: 0, failed: 0 });
        assert_eq!(store.preview_counts(&req.run_id).unwrap().failed, 0);

        let mut saw_throttled = false;
        while let Ok(event) = rx.try_recv() {
            if matches!(event, ProgressEvent::Throttled { wait_secs: 0, .. }) {
                saw_throttled = true;
            }
        }
        assert!(saw_throttled, "rate-limit event must reach progress stream");
    }

    #[tokio::test]
    async fn execute_keeps_protected_rows_and_locks_the_preview() {
        let adapter: Arc<dyn PlatformAdapter> = Arc::new(FakeAdapter::with_items(2));
        let mut store = Store::open_in_memory("test-key").unwrap();
        let mut scheduler = Scheduler::new();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();

        let req = RunRequest {
            run_id: "lock".into(),
            platform: "fake".into(),
            account_id: "fake:a".into(),
            account_label: "acc".into(),
            plan: EnumeratePlan::default(),
            filter: match_all_filter(),
            backup: false,
            allow_incomplete_backup: false,
            allow_lost_files: false,
        };
        store
            .create_run(&NewRun {
                run_id: req.run_id.clone(),
                platform: req.platform.clone(),
                account: req.account_label.clone(),
                filter_json: "{}".into(),
                started_secs: 0,
            })
            .unwrap();
        snapshot(adapter.clone(), &store, &req, &tx).await.unwrap();

        let query = ItemQuery { limit: 10, ..Default::default() };
        let kept = store.preview_items(&req.run_id, &query).unwrap().remove(0).platform_id;
        assert!(store.set_item_protected(&req.run_id, &kept, true).unwrap());

        let outcome = execute(
            adapter,
            &mut store,
            &mut scheduler,
            &req,
            RunControl::new(),
            &tx,
            None,
        )
        .await
        .unwrap();

        assert_eq!(outcome, RunOutcome { deleted: 1, skipped: 0, failed: 0 });
        assert!(!store.set_item_protected(&req.run_id, &kept, false).unwrap());
        assert_eq!(store.preview_counts(&req.run_id).unwrap().protected, 1);
    }

    /// Adapter whose items carry files, with scripted fetches and a call journal.
    pub(super) struct MediaAdapter {
        inner: FakeAdapter,
        items: Vec<Item>,
        fetch: Box<dyn Fn(&MediaRef, usize) -> std::result::Result<FetchedMedia, AdapterError> + Send + Sync>,
        delete_rate_limits: AtomicUsize,
        fetches: AtomicUsize,
        journal: Mutex<Vec<String>>,
    }

    impl MediaAdapter {
        pub(super) fn new(
            items: Vec<Item>,
            fetch: impl Fn(&MediaRef, usize) -> std::result::Result<FetchedMedia, AdapterError> + Send + Sync + 'static,
        ) -> Self {
            Self {
                inner: FakeAdapter::with_items(0),
                items,
                fetch: Box::new(fetch),
                delete_rate_limits: AtomicUsize::new(0),
                fetches: AtomicUsize::new(0),
                journal: Mutex::new(Vec::new()),
            }
        }

        pub(super) fn journal(&self) -> Vec<String> {
            self.journal.lock().unwrap().clone()
        }

        fn note(&self, entry: String) {
            self.journal.lock().unwrap().push(entry);
        }
    }

    #[async_trait]
    impl PlatformAdapter for MediaAdapter {
        fn descriptor(&self) -> &Descriptor {
            self.inner.descriptor()
        }

        async fn enumerate(&self, _plan: &EnumeratePlan) -> std::result::Result<ItemStream, AdapterError> {
            Ok(Box::pin(stream::iter(self.items.clone().into_iter().map(Ok))))
        }

        async fn delete(&self, items: &[ItemRef]) -> Vec<Outcome> {
            if self.delete_rate_limits.load(Ordering::SeqCst) > 0 {
                self.delete_rate_limits.fetch_sub(1, Ordering::SeqCst);
                return items.iter().map(|_| Outcome::RateLimited { retry_after_secs: 0 }).collect();
            }
            items
                .iter()
                .map(|item| {
                    self.note(format!("delete {}", item.platform_id));
                    Outcome::Deleted
                })
                .collect()
        }

        async fn fetch_media(
            &self,
            _item: &ItemRef,
            media: &MediaRef,
        ) -> std::result::Result<FetchedMedia, AdapterError> {
            self.note(format!("fetch {}", media.url));
            (self.fetch)(media, self.fetches.fetch_add(1, Ordering::SeqCst))
        }

        async fn release_media(&self, file: &FetchedMedia) -> std::result::Result<(), AdapterError> {
            self.note(format!("release {}", file.handle));
            std::fs::remove_file(&file.path).ok();
            Ok(())
        }

        fn rate_policy(&self) -> RatePolicy {
            self.inner.rate_policy()
        }
    }

    pub(super) fn media_item(id: &str, files: &[(&str, u64)]) -> Item {
        Item {
            content_type: ContentType::Media,
            created_at: None,
            text: Some(format!("caption {id}")),
            engagement: Engagement::default(),
            scope_id: None,
            media: files
                .iter()
                .map(|(url, size)| MediaRef {
                    url: (*url).into(),
                    mime: Some("image/jpeg".into()),
                    file_name: Some(format!("{url}.jpg")),
                    size: Some(*size),
                })
                .collect(),
            platform_record: None,
            backup_gap: None,
            item_ref: ItemRef { platform_id: id.into(), token: None },
        }
    }

    /// Writes a downloaded file for an adapter to hand over.
    pub(super) fn downloaded(bytes: &[u8]) -> FetchedMedia {
        let path = std::env::temp_dir().join(format!("lethe-media-{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, bytes).unwrap();
        FetchedMedia { path, handle: 1 }
    }

    pub(super) struct MediaRun {
        pub(super) outcome: Result<RunOutcome>,
        pub(super) store: Store,
        events: Vec<ProgressEvent>,
        pub(super) archive: PathBuf,
    }

    pub(super) const ARCHIVE_KEY: DataKey = [5u8; 32];

    pub(super) async fn run_media(adapter: Arc<MediaAdapter>, control: RunControl) -> MediaRun {
        run_media_with_consent(adapter, control, false).await
    }

    /// A run in which the person agreed to delete items that lost a file.
    pub(super) async fn run_media_allowing_lost_files(adapter: Arc<MediaAdapter>) -> MediaRun {
        run_media_request(adapter, RunControl::new(), false, true, true).await
    }

    async fn run_media_with_consent(
        adapter: Arc<MediaAdapter>,
        control: RunControl,
        allow_incomplete_backup: bool,
    ) -> MediaRun {
        run_media_on(adapter, control, allow_incomplete_backup, true).await
    }

    async fn run_media_on(
        adapter: Arc<MediaAdapter>,
        control: RunControl,
        allow_incomplete_backup: bool,
        with_backup: bool,
    ) -> MediaRun {
        run_media_request(adapter, control, allow_incomplete_backup, false, with_backup).await
    }

    async fn run_media_request(
        adapter: Arc<MediaAdapter>,
        control: RunControl,
        allow_incomplete_backup: bool,
        allow_lost_files: bool,
        with_backup: bool,
    ) -> MediaRun {
        let mut store = Store::open_in_memory("test-key").unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let req = RunRequest {
            run_id: "media".into(),
            platform: "fake".into(),
            account_id: "fake:a".into(),
            account_label: "acc".into(),
            plan: EnumeratePlan::default(),
            filter: match_all_filter(),
            backup: true,
            allow_incomplete_backup,
            allow_lost_files,
        };
        store
            .create_run(&NewRun {
                run_id: req.run_id.clone(),
                platform: req.platform.clone(),
                account: req.account_label.clone(),
                filter_json: "{}".into(),
                started_secs: 0,
            })
            .unwrap();
        let archive = std::env::temp_dir().join(format!("lethe-archive-{}", uuid::Uuid::new_v4()));
        snapshot(adapter.clone(), &store, &req, &tx).await.unwrap();
        let outcome = execute(
            adapter,
            &mut store,
            &mut Scheduler::new(),
            &req,
            control,
            &tx,
            with_backup.then(|| BackupTarget { path: archive.clone(), key: ARCHIVE_KEY }),
        )
        .await;
        let mut events = Vec::new();
        while let Ok(event) = rx.try_recv() {
            events.push(event);
        }
        MediaRun { outcome, store, events, archive }
    }

    impl Drop for MediaRun {
        fn drop(&mut self) {
            std::fs::remove_file(&self.archive).ok();
        }
    }

    impl MediaRun {
        pub(super) fn audit(&self) -> crate::archive::ArchiveAudit {
            audit_archive(File::open(&self.archive).unwrap(), &ARCHIVE_KEY).unwrap()
        }

        fn chunks(&self) -> Vec<Vec<u8>> {
            let mut reader = ContainerReader::open(File::open(&self.archive).unwrap(), &ARCHIVE_KEY).unwrap();
            let mut chunks = Vec::new();
            while let Some(chunk) = reader.read_chunk().unwrap() {
                chunks.push(chunk);
            }
            chunks
        }
    }

    #[tokio::test]
    async fn files_reach_the_archive_before_their_message_is_deleted() {
        // Spans a chunk boundary, so the file has to be split and put back together.
        let bytes: Vec<u8> = (0..1024 * 1024 + 300).map(|i| (i % 251) as u8).collect();
        let source = bytes.clone();
        let adapter = Arc::new(MediaAdapter::new(
            vec![media_item("m1", &[("photo", bytes.len() as u64)])],
            move |_, _| Ok(downloaded(&source)),
        ));

        let run = run_media(adapter.clone(), RunControl::new()).await;

        assert_eq!(run.outcome.as_ref().unwrap(), &RunOutcome { deleted: 1, skipped: 0, failed: 0 });
        assert_eq!(adapter.journal(), ["fetch photo", "release 1", "delete m1"]);

        let chunks = run.chunks();
        let record: serde_json::Value = serde_json::from_slice(&chunks[1]).unwrap();
        assert_eq!(record["text"], "caption m1");
        assert_eq!(record["media"][0]["file_name"], "photo.jpg");
        assert_eq!(record["media"][0]["archived_bytes"], bytes.len() as u64);
        assert_eq!(record["media"][0]["chunks"], 2);
        assert_eq!(chunks[2..].concat(), bytes);
        assert_eq!(run.audit().media_files, 1);
        assert!(run.events.iter().any(|event| matches!(
            event,
            ProgressEvent::Archiving { done_bytes, total_bytes } if *done_bytes == *total_bytes && *total_bytes == bytes.len() as u64
        )));
    }

    #[tokio::test]
    async fn the_platform_record_reaches_the_archive_before_the_delete() {
        let poll = Item {
            platform_record: Some(
                PlatformRecord::from_json(r#"{"question":"tea or coffee","votes":[3,4]}"#.into()).unwrap(),
            ),
            ..media_item("poll", &[])
        };
        let adapter = Arc::new(MediaAdapter::new(vec![poll, media_item("plain", &[])], |_, _| {
            Ok(downloaded(b""))
        }));

        let run = run_media(adapter.clone(), RunControl::new()).await;

        assert_eq!(run.outcome.as_ref().unwrap(), &RunOutcome { deleted: 2, skipped: 0, failed: 0 });
        let records: Vec<serde_json::Value> = run.chunks()[1..]
            .iter()
            .map(|chunk| serde_json::from_slice(chunk).unwrap())
            .collect();
        let of = |id: &str| records.iter().find(|record| record["platform_id"] == id).unwrap();
        assert_eq!(of("poll")["platform_record"]["question"], "tea or coffee");
        assert_eq!(of("poll")["platform_record"]["votes"][1], 4);
        assert!(of("plain").get("platform_record").is_none());
        assert_eq!(run.audit().items, 2);
    }

    fn item_with_a_gap(id: &str) -> Item {
        Item {
            backup_gap: Some("Telegram does not hand over this file".into()),
            ..media_item(id, &[("photo", 3)])
        }
    }

    #[tokio::test]
    async fn an_item_the_backup_cannot_hold_stays_without_consent() {
        let adapter = Arc::new(MediaAdapter::new(
            vec![item_with_a_gap("gap"), media_item("whole", &[])],
            |_, _| Ok(downloaded(b"abc")),
        ));

        let run = run_media(adapter.clone(), RunControl::new()).await;

        assert_eq!(run.outcome.as_ref().unwrap(), &RunOutcome { deleted: 1, skipped: 0, failed: 0 });
        assert_eq!(adapter.journal(), ["delete whole"]);
        assert_eq!(run.store.preview_counts("media").unwrap().protected, 1);
        assert_eq!(run.audit().items, 1);
    }

    #[tokio::test]
    async fn a_run_with_no_backup_at_all_still_needs_consent_for_such_an_item() {
        let adapter = Arc::new(MediaAdapter::new(vec![item_with_a_gap("gap")], |_, _| {
            Ok(downloaded(b"abc"))
        }));

        let run = run_media_on(adapter.clone(), RunControl::new(), false, false).await;

        assert_eq!(run.outcome.as_ref().unwrap(), &RunOutcome { deleted: 0, skipped: 0, failed: 0 });
        assert!(adapter.journal().is_empty());
    }

    #[tokio::test]
    async fn an_item_the_backup_cannot_hold_goes_with_consent_and_says_what_is_missing() {
        let adapter = Arc::new(MediaAdapter::new(vec![item_with_a_gap("gap")], |_, _| {
            Ok(downloaded(b"abc"))
        }));

        let run = run_media_with_consent(adapter.clone(), RunControl::new(), true).await;

        assert_eq!(run.outcome.as_ref().unwrap(), &RunOutcome { deleted: 1, skipped: 0, failed: 0 });
        assert_eq!(adapter.journal(), ["fetch photo", "release 1", "delete gap"]);
        let record: serde_json::Value = serde_json::from_slice(&run.chunks()[1]).unwrap();
        assert_eq!(record["backup_gap"], "Telegram does not hand over this file");
        assert_eq!(run.audit().media_files, 1);
    }

    #[tokio::test]
    async fn a_file_that_cannot_be_fetched_keeps_its_message() {
        let adapter = Arc::new(MediaAdapter::new(
            vec![media_item("kept", &[("bad", 3)]), media_item("gone", &[("good", 3)])],
            |media, _| match media.url.as_str() {
                "bad" => Err(AdapterError::Platform("file expired".into())),
                _ => Ok(downloaded(b"abc")),
            },
        ));

        let run = run_media(adapter.clone(), RunControl::new()).await;

        assert_eq!(run.outcome.as_ref().unwrap(), &RunOutcome { deleted: 1, skipped: 0, failed: 1 });
        assert!(!adapter.journal().contains(&"delete kept".to_string()));
        assert!(adapter.journal().contains(&"delete gone".to_string()));
        assert_eq!(run.store.preview_counts("media").unwrap().failed, 1);
        assert_eq!(run.audit().items, 1, "a message that stays has no entry in the backup");
    }

    #[tokio::test]
    async fn a_later_file_failing_removes_the_earlier_download_and_writes_nothing() {
        let adapter = Arc::new(MediaAdapter::new(
            vec![media_item("album", &[("first", 3), ("second", 3)])],
            |media, _| match media.url.as_str() {
                "first" => Ok(downloaded(b"abc")),
                _ => Err(AdapterError::Platform("file expired".into())),
            },
        ));

        let run = run_media(adapter.clone(), RunControl::new()).await;

        assert_eq!(run.outcome.as_ref().unwrap().failed, 1);
        assert_eq!(adapter.journal(), ["fetch first", "fetch second", "release 1"]);
        assert_eq!(run.audit().items, 0);
    }

    #[tokio::test]
    async fn a_message_gone_before_its_file_is_fetched_counts_as_skipped() {
        let adapter = Arc::new(MediaAdapter::new(
            vec![media_item("m1", &[("photo", 3)])],
            |_, _| Err(AdapterError::NotFound),
        ));

        let run = run_media(adapter, RunControl::new()).await;

        assert_eq!(run.outcome.as_ref().unwrap(), &RunOutcome { deleted: 0, skipped: 1, failed: 0 });
    }

    #[tokio::test]
    async fn a_rate_limited_fetch_is_retried_without_losing_the_item() {
        let adapter = Arc::new(MediaAdapter::new(
            vec![media_item("m1", &[("photo", 3)])],
            |_, call| match call {
                0 => Err(AdapterError::RateLimited { retry_after_secs: 0 }),
                _ => Ok(downloaded(b"abc")),
            },
        ));

        let run = run_media(adapter, RunControl::new()).await;

        assert_eq!(run.outcome.as_ref().unwrap(), &RunOutcome { deleted: 1, skipped: 0, failed: 0 });
        assert_eq!(run.audit(), crate::archive::ArchiveAudit { items: 1, media_files: 1 });
    }

    #[tokio::test]
    async fn a_rate_limited_delete_does_not_archive_the_item_twice() {
        let adapter = Arc::new(MediaAdapter::new(
            vec![media_item("m1", &[("photo", 3)])],
            |_, _| Ok(downloaded(b"abc")),
        ));
        adapter.delete_rate_limits.store(1, Ordering::SeqCst);

        let run = run_media(adapter.clone(), RunControl::new()).await;

        assert_eq!(run.outcome.as_ref().unwrap(), &RunOutcome { deleted: 1, skipped: 0, failed: 0 });
        assert_eq!(run.audit(), crate::archive::ArchiveAudit { items: 1, media_files: 1 });
        assert_eq!(adapter.fetches.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn stopping_between_downloads_leaves_a_sealed_archive() {
        let control = RunControl::new();
        let stop = control.clone();
        let adapter = Arc::new(MediaAdapter::new(
            vec![media_item("m1", &[("photo", 3)]), media_item("m2", &[("video", 3)])],
            move |_, _| {
                stop.stop();
                Ok(downloaded(b"abc"))
            },
        ));

        let run = run_media(adapter.clone(), control).await;

        assert!(matches!(run.outcome, Err(EngineError::Aborted)));
        assert_eq!(run.audit().items, 1);
        assert!(adapter.journal().iter().all(|entry| !entry.starts_with("delete")));
        assert_eq!(run.store.preview_counts("media").unwrap().pending, 2);
    }

    /// Exports the run's archive and returns the folder's report and `messages.txt`.
    fn exported(run: &MediaRun) -> (crate::archive::ExportReport, String) {
        let parent = std::env::temp_dir().join(format!("lethe-run-export-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&parent).unwrap();
        let report = crate::archive::ArchiveExport::open(File::open(&run.archive).unwrap(), &ARCHIVE_KEY)
            .unwrap()
            .write_to(&parent, "export")
            .unwrap();
        let messages = std::fs::read_to_string(report.folder.join("messages.txt")).unwrap();
        (report, messages)
    }

    #[tokio::test]
    async fn what_a_run_deleted_comes_back_out_of_its_backup() {
        let bytes: Vec<u8> = (0..1024 * 1024 + 300).map(|i| (i % 251) as u8).collect();
        let source = bytes.clone();
        let adapter = Arc::new(MediaAdapter::new(
            vec![media_item("m1", &[("photo", bytes.len() as u64)])],
            move |_, _| Ok(downloaded(&source)),
        ));

        let run = run_media(adapter, RunControl::new()).await;
        assert_eq!(run.outcome.as_ref().unwrap(), &RunOutcome { deleted: 1, skipped: 0, failed: 0 });

        let (report, messages) = exported(&run);
        assert!(report.complete);
        assert!(messages.contains("caption m1"));
        assert_eq!(std::fs::read(report.folder.join("files/photo.jpg")).unwrap(), bytes);
        std::fs::remove_dir_all(report.folder.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn a_stopped_run_exports_what_it_got_to() {
        let control = RunControl::new();
        let stop = control.clone();
        let adapter = Arc::new(MediaAdapter::new(
            vec![media_item("m1", &[("photo", 3)]), media_item("m2", &[("video", 3)])],
            move |_, _| {
                stop.stop();
                Ok(downloaded(b"abc"))
            },
        ));

        let run = run_media(adapter, control).await;
        assert!(matches!(run.outcome, Err(EngineError::Aborted)));

        let (report, messages) = exported(&run);
        assert_eq!(report.items, 1);
        assert_eq!(report.media_files, 1);
        assert!(messages.contains("caption m1"));
        assert!(!messages.contains("caption m2"));
        std::fs::remove_dir_all(report.folder.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn stopping_during_the_last_download_deletes_nothing() {
        let control = RunControl::new();
        let stop = control.clone();
        let adapter = Arc::new(MediaAdapter::new(
            vec![media_item("m1", &[("photo", 3)])],
            move |_, _| {
                stop.stop();
                Ok(downloaded(b"abc"))
            },
        ));

        let run = run_media(adapter.clone(), control).await;

        assert!(matches!(run.outcome, Err(EngineError::Aborted)));
        assert!(adapter.journal().iter().all(|entry| !entry.starts_with("delete")));
        assert_eq!(run.store.preview_counts("media").unwrap().pending, 1);
    }

    #[tokio::test]
    async fn stopping_between_files_of_a_message_fetches_no_more_of_them() {
        let control = RunControl::new();
        let stop = control.clone();
        let adapter = Arc::new(MediaAdapter::new(
            vec![media_item("album", &[("first", 3), ("second", 3)])],
            move |_, _| {
                stop.stop();
                Ok(downloaded(b"abc"))
            },
        ));

        let run = run_media(adapter.clone(), control).await;

        assert!(matches!(run.outcome, Err(EngineError::Aborted)));
        assert_eq!(adapter.journal(), ["fetch first", "release 1"]);
        assert_eq!(run.audit().items, 0);
    }
}

//! Two-phase run. `snapshot` (Phase 1) builds the immutable preview; `execute`
//! (Phase 2) acts on exactly the rows still `pending`. dry-run == executed is
//! structural: the preview IS the snapshot the executor reads.

use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use lethe_adapter::{EnumeratePlan, Item, Outcome, PlatformAdapter};
use lethe_crypto::container::ContainerWriter;
use lethe_crypto::receipt::{ReceiptSigner, RunSummary, SignedReceipt};
use lethe_crypto::DataKey;
use lethe_store::{ItemSnapshot, ItemState, PreviewCounts, Store};

use crate::filter::{FilterSpec, Predicate};
use crate::scheduler::Scheduler;
use crate::{EngineError, ProgressEvent, ProgressTx, Result, RunControl};

const SNAPSHOT_FLUSH: usize = 500;
const DELETE_BATCH: usize = 100;

pub struct RunRequest {
    pub run_id: String,
    pub platform: String,
    pub account_id: String,
    pub account_label: String,
    pub plan: EnumeratePlan,
    pub filter: FilterSpec,
    pub backup: bool,
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

#[derive(serde::Serialize)]
struct BackupManifest<'a> {
    run_id: &'a str,
    platform: &'a str,
    account_label: &'a str,
}

#[derive(serde::Serialize)]
struct BackupItem<'a> {
    platform_id: &'a str,
    token: Option<&'a str>,
}

fn to_json(value: &impl serde::Serialize) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|e| EngineError::Io(e.to_string()))
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
    let total = store.preview_counts(&req.run_id)?.pending;
    let mut outcome = RunOutcome::default();

    // Open the encrypted backup up front (FR-BAK-1, on-by-default): if a target
    // is given and the run requests backup, every batch is archived BEFORE its
    // delete, so an interrupted run never deletes anything it has not backed up.
    let mut writer = match (&backup, req.backup) {
        (Some(target), true) => {
            let file =
                File::create(&target.path).map_err(|e| EngineError::Io(e.to_string()))?;
            let mut w = ContainerWriter::create(file, &target.key)?;
            let manifest = BackupManifest {
                run_id: &req.run_id,
                platform: &req.platform,
                account_label: &req.account_label,
            };
            w.write_chunk(&to_json(&manifest)?)?;
            Some(w)
        }
        _ => None,
    };

    loop {
        if control.is_stopped() {
            return Err(EngineError::Aborted);
        }
        if control.is_paused() {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            continue;
        }

        let batch = store.claim_pending_batch(&req.run_id, DELETE_BATCH)?;
        if batch.is_empty() {
            break;
        }

        // Backup-before-delete. (Media-blob capture is still TODO: it needs the
        // enumerated content persisted in Phase 1; today we archive the item
        // refs, which is the deletion manifest for legal handoff.)
        if let Some(w) = writer.as_mut() {
            for item in &batch {
                let record = BackupItem {
                    platform_id: &item.platform_id,
                    token: item.token.as_deref(),
                };
                w.write_chunk(&to_json(&record)?)?;
            }
        }

        // Rate gate (one token per delete call; adapter batches internally).
        scheduler.bucket(&req.account_id, &policy).acquire().await;

        let outcomes = adapter.delete(&batch).await;

        // Terminal outcomes are checkpointed. Rate-limited items stay pending
        // and are retried after the scheduler applies the platform delay.
        let mut records = Vec::with_capacity(outcomes.len());
        let mut retry_after_secs: Option<u64> = None;
        for (item, result) in batch.iter().zip(outcomes) {
            match &result {
                Outcome::Deleted => outcome.deleted += 1,
                Outcome::Skipped { .. } => outcome.skipped += 1,
                Outcome::Failed { .. } => outcome.failed += 1,
                Outcome::RateLimited { retry_after_secs: secs } => {
                    retry_after_secs = Some(retry_after_secs.map_or(*secs, |current| current.max(*secs)));
                    continue;
                }
            }
            records.push((item.platform_id.clone(), result));
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

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use futures::stream;
    use lethe_adapter::{
        AdapterError, Capabilities, ContentType, Descriptor, Engagement, ItemRef, ItemStream,
        RatePolicy, RiskClass,
    };
    use lethe_crypto::container::ContainerReader;
    use lethe_crypto::receipt::{verify, ReceiptSigner, RunSummary};
    use lethe_store::{NewRun, Store};
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
        while reader.read_chunk().unwrap().is_some() {
            chunks += 1;
        }
        assert_eq!(chunks, n + 1, "manifest + one record per deleted item");
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
}

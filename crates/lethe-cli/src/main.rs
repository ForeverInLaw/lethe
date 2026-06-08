//! Headless vertical runner. Wires egress allowlist from the adapter
//! descriptor, runs Phase 1 (snapshot/preview) then Phase 2 (execute), and
//! prints progress. CI runs this inside a network sandbox.

use std::sync::Arc;

use async_trait::async_trait;
use lethe_adapter::{Consent, PlatformAdapter};
use lethe_bluesky::BlueskyAdapter;
use lethe_core::pipeline::{self, RunRequest};
use lethe_core::scheduler::Scheduler;
use lethe_core::{ProgressEvent, RunControl};
use lethe_net::Egress;
use lethe_store::Store;

/// Stdin/env consent for headless auth (app-password, login codes).
struct CliConsent;

#[async_trait]
impl Consent for CliConsent {
    async fn confirm(&self, prompt: &str) -> bool {
        eprintln!("[consent] {prompt} -> assuming yes (headless)");
        true
    }
    async fn input(&self, prompt: &str, _secret: bool) -> Option<String> {
        // TODO(cli): read from env (LETHE_BSKY_IDENT / LETHE_BSKY_APP_PASSWORD).
        eprintln!("[input] {prompt}");
        None
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let pds_host = std::env::var("LETHE_PDS_HOST").unwrap_or_else(|_| "bsky.social".into());

    // Build the adapter, then seed egress from its declared endpoints.
    let allow_seed: Vec<String> = {
        let probe = BlueskyAdapter::new(Arc::new(Egress::new(std::iter::empty())), &pds_host);
        probe.descriptor().endpoints.iter().map(|e| e.host.clone()).collect()
    };
    let egress = Arc::new(Egress::new(allow_seed));
    let adapter: Arc<dyn PlatformAdapter> =
        Arc::new(BlueskyAdapter::new(egress.clone(), &pds_host));

    let store = Store::open_in_memory("dev-key")?;
    let mut store = store;
    let mut scheduler = Scheduler::new();
    let control = RunControl::new();
    let _consent = CliConsent; // used once auth wiring lands

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ProgressEvent>();
    let printer = tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            println!("{ev:?}");
        }
    });

    let req = RunRequest {
        run_id: "dev-run".into(),
        platform: "bluesky".into(),
        account_id: "bluesky:dev".into(),
        account_label: "dev".into(),
        plan: Default::default(),
        filter: dev_filter(),
        backup: true,
    };

    store.create_run(&lethe_store::NewRun {
        run_id: req.run_id.clone(),
        platform: req.platform.clone(),
        account: req.account_label.clone(),
        filter_json: "{}".into(),
        started_secs: 0,
    })?;

    let counts = pipeline::snapshot(adapter.clone(), &store, &req, &tx).await?;
    println!("preview: {counts:?}");

    // No backup target in the headless CLI run (no passphrase prompt); the
    // engine archives nothing but still produces a signed receipt below.
    let outcome =
        pipeline::execute(adapter, &mut store, &mut scheduler, &req, control, &tx, None).await?;
    println!("outcome: {outcome:?}");

    // Receipt = per-install Ed25519 over a counts-only summary. The CLI owns the
    // clock + identity; a real build loads the signer from the OS keychain.
    let signer = lethe_crypto::receipt::ReceiptSigner::generate();
    let summary = lethe_crypto::receipt::RunSummary {
        run_id: req.run_id.clone(),
        platform: req.platform.clone(),
        account_label: req.account_label.clone(),
        started_epoch_secs: 0,
        finished_epoch_secs: now_secs(),
        deleted: outcome.deleted,
        skipped: outcome.skipped,
        failed: outcome.failed,
    };
    let receipt = pipeline::store_receipt(&store, &signer, &summary)?;
    println!("receipt public key: {}", receipt.public_key_hex);

    drop(tx);
    let _ = printer.await;
    Ok(())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn dev_filter() -> lethe_core::filter::FilterSpec {
    lethe_core::filter::FilterSpec {
        content_types: Default::default(),
        date_from: None,
        date_to: None,
        keyword: None,
        engagement_max: None,
        allowlist_ids: Default::default(),
    }
}

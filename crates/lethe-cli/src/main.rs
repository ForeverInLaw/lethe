//! Headless vertical runner. Wires egress allowlist from the adapter
//! descriptor, runs Phase 1 (snapshot/preview) then Phase 2 (execute), and
//! prints progress. CI runs this inside a network sandbox.

use std::{env, sync::Arc};

use anyhow::{bail, ensure};
use async_trait::async_trait;
use lethe_adapter::{AuthProvider, Consent, PlatformAdapter};
use lethe_bluesky::{BlueskyAdapter, BlueskyAuth};
use lethe_core::pipeline::{self, RunRequest};
use lethe_core::scheduler::Scheduler;
use lethe_core::{ProgressEvent, RunControl};
use lethe_net::{Egress, EgressError};
use lethe_store::Store;

/// Stdin/env consent for headless auth (app-password, login codes).
struct CliConsent;

#[async_trait]
impl Consent for CliConsent {
    async fn confirm(&self, prompt: &str) -> bool {
        eprintln!("[consent] {prompt} -> assuming yes (headless)");
        true
    }
    async fn input(&self, prompt: &str, secret: bool) -> Option<String> {
        let key = env_key_for_prompt(prompt, secret)?;
        match env::var(key) {
            Ok(value) if !value.is_empty() => Some(value),
            _ => {
                eprintln!("[input] {prompt}: missing {key}");
                None
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let pds_host = env::var("LETHE_PDS_HOST").unwrap_or_else(|_| "bsky.social".into());

    // Build the adapter, then seed egress from its declared endpoints.
    let allow_seed: Vec<String> = {
        let probe = BlueskyAdapter::new(Arc::new(Egress::new(std::iter::empty())), &pds_host);
        probe.descriptor().endpoints.iter().map(|e| e.host.clone()).collect()
    };
    let egress = Arc::new(Egress::new(allow_seed));

    if env::args().any(|arg| arg == "--ci-egress-probe") {
        ci_egress_probe(&egress).await?;
        return Ok(());
    }

    let consent = CliConsent;
    let auth = BlueskyAuth::new(egress.clone());
    let credential = auth.connect(&consent).await?;

    let mut adapter = BlueskyAdapter::new(egress.clone(), &pds_host);
    adapter.authenticate(&credential).await?;
    let adapter: Arc<dyn PlatformAdapter> = Arc::new(adapter);

    let store = Store::open_in_memory("dev-key")?;
    let mut store = store;
    let mut scheduler = Scheduler::new();
    let control = RunControl::new();

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ProgressEvent>();
    let printer = tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            println!("{ev:?}");
        }
    });

    let run_id = env::var("LETHE_RUN_ID").unwrap_or_else(|_| format!("cli-{}", now_secs()));
    let req = RunRequest {
        run_id,
        platform: "bluesky".into(),
        account_id: format!("bluesky:{}", credential.account_label),
        account_label: credential.account_label,
        plan: Default::default(),
        filter: dev_filter(),
        backup: true,
        allow_incomplete_backup: false,
        allow_lost_files: false,
        allow_only_for_self: false,
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

    ensure!(
        env::var("LETHE_CLI_CONFIRM_DELETE").as_deref() == Ok(req.run_id.as_str()),
        "preview complete; set LETHE_CLI_CONFIRM_DELETE={} to execute deletion",
        req.run_id
    );

    // No backup target in the headless CLI run (no passphrase prompt); the
    // engine archives nothing but still produces a signed receipt below.
    let outcome =
        pipeline::execute(adapter, &mut store, &mut scheduler, &req, control, &tx, None).await?;
    println!("outcome: {outcome:?}");

    // Receipt = per-install Ed25519 over a counts-only summary. The CLI owns the
    // clock + identity; a real build loads the signer from the OS keychain.
    let signer = lethe_crypto::receipt::ReceiptSigner::generate();
    let summary = outcome.summary(&req, 0, now_secs());
    let receipt = pipeline::store_receipt(&store, &signer, &summary)?;
    println!("receipt public key: {}", receipt.public_key_hex);

    drop(tx);
    let _ = printer.await;
    Ok(())
}

async fn ci_egress_probe(egress: &Egress) -> anyhow::Result<()> {
    ensure!(egress.allows("bsky.social"), "Bluesky entryway missing from allowlist");
    ensure!(
        !egress.allows("example.com"),
        "blocked probe host unexpectedly present in allowlist"
    );

    let req = reqwest::Request::new(reqwest::Method::GET, "https://example.com/".parse()?);
    match egress.execute(req).await {
        Err(EgressError::Blocked(host)) if host == "example.com" => {}
        Err(other) => bail!("blocked probe returned unexpected error: {other}"),
        Ok(_) => bail!("blocked probe unexpectedly reached the network"),
    }

    let blocked = egress
        .log()
        .into_iter()
        .any(|record| record.host == "example.com" && !record.allowed);
    ensure!(blocked, "blocked probe was not recorded in the egress log");

    println!("ci egress probe: ok");
    Ok(())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn env_key_for_prompt(prompt: &str, secret: bool) -> Option<&'static str> {
    let prompt = prompt.to_ascii_lowercase();
    if prompt.contains("handle") || prompt.contains("email") {
        Some("LETHE_BSKY_IDENT")
    } else if secret || prompt.contains("password") {
        Some("LETHE_BSKY_APP_PASSWORD")
    } else {
        None
    }
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

#[cfg(test)]
mod tests {
    use super::env_key_for_prompt;

    #[test]
    fn maps_bluesky_prompts_to_env() {
        assert_eq!(
            env_key_for_prompt("Bluesky handle or email", false),
            Some("LETHE_BSKY_IDENT")
        );
        assert_eq!(
            env_key_for_prompt("Bluesky app password", true),
            Some("LETHE_BSKY_APP_PASSWORD")
        );
    }
}

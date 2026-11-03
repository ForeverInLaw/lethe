//! Lethe engine core.

pub mod archive;
pub mod filter;
pub mod pipeline;
pub mod scheduler;

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

pub use lethe_net::Egress;

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error(transparent)]
    Filter(#[from] filter::FilterError),
    #[error(transparent)]
    Store(#[from] lethe_store::StoreError),
    /// The platform stopped the work; the app tells the person why from its kind.
    #[error("adapter: {0}")]
    Adapter(lethe_adapter::AdapterError),
    #[error(transparent)]
    Crypto(#[from] lethe_crypto::CryptoError),
    #[error("backup io: {0}")]
    Io(String),
    #[error("aborted by user")]
    Aborted,
}

pub type Result<T> = std::result::Result<T, EngineError>;

/// Live run telemetry. The app forwards these to the Tauri `Channel`.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
pub enum ProgressEvent {
    Enumerating { seen: u64 },
    PreviewReady { pending: u64, protected: u64 },
    /// Media files going into the backup, in expected bytes.
    Archiving { done_bytes: u64, total_bytes: u64 },
    Deleting { deleted: u64, skipped: u64, failed: u64, total: u64 },
    Throttled { rate_per_sec: f64, wait_secs: u64 },
    /// The platform stopped answering; the run waits for it without failing items.
    Offline,
    /// The platform answers again after `Offline`; the run goes on.
    Online,
    Done { run_id: String },
}

pub type ProgressTx = tokio::sync::mpsc::UnboundedSender<ProgressEvent>;

/// Cooperative pause/stop/resume. The pipeline checks this between batches; the
/// run survives UI navigation because this handle lives in the core, not the UI.
#[derive(Clone, Default)]
pub struct RunControl(Arc<AtomicU8>);

/// How soon a stop is noticed by work that waits.
pub(crate) const STOP_POLL: std::time::Duration = std::time::Duration::from_millis(200);

const RUN: u8 = 0;
const PAUSE: u8 = 1;
const STOP: u8 = 2;

impl RunControl {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn pause(&self) {
        self.0.store(PAUSE, Ordering::SeqCst);
    }
    pub fn resume(&self) {
        self.0.store(RUN, Ordering::SeqCst);
    }
    pub fn stop(&self) {
        self.0.store(STOP, Ordering::SeqCst);
    }
    pub fn is_stopped(&self) -> bool {
        self.0.load(Ordering::SeqCst) == STOP
    }
    pub fn is_paused(&self) -> bool {
        self.0.load(Ordering::SeqCst) == PAUSE
    }
    /// Completes once the run has been stopped, for work that must be called off
    /// mid-way, such as a download.
    pub async fn stopped(&self) {
        while !self.is_stopped() {
            tokio::time::sleep(STOP_POLL).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::RunControl;

    #[tokio::test(start_paused = true)]
    async fn stopped_completes_once_the_run_is_stopped_and_not_on_a_pause() {
        let control = RunControl::new();
        let waiting = tokio::spawn({
            let control = control.clone();
            async move { control.stopped().await }
        });

        control.pause();
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(!waiting.is_finished());

        control.stop();
        tokio::time::timeout(Duration::from_secs(1), waiting).await.unwrap().unwrap();
    }
}

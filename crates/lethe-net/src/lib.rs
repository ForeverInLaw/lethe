//! The single egress chokepoint.
//!
//! Every adapter routes network through one shared `Egress`. The allowlist is
//! the union of active adapters' declared endpoints. The in-process host check
//! here is *defense-in-depth* and the source of the trust-panel request log —
//! the **authoritative** guarantee is the CI network sandbox (the build fails
//! on any connection outside the allowlist).

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;

#[derive(Debug, thiserror::Error)]
pub enum EgressError {
    #[error("blocked: host '{0}' is not on the egress allowlist")]
    Blocked(String),
    #[error("request has no host")]
    NoHost,
    #[error(transparent)]
    Http(#[from] reqwest::Error),
}

#[derive(Debug, Clone)]
pub struct EgressRecord {
    pub host: String,
    pub method: String,
    pub allowed: bool,
    pub at_epoch_secs: u64,
}

pub struct Egress {
    client: reqwest::Client,
    allow: HashSet<String>,
    log: Mutex<Vec<EgressRecord>>,
}

impl Egress {
    pub fn new(allow: impl IntoIterator<Item = String>) -> Self {
        let client = reqwest::Client::builder()
            .user_agent(concat!("lethe/", env!("CARGO_PKG_VERSION")))
            .use_rustls_tls()
            .build()
            .expect("reqwest client");
        Self {
            client,
            allow: allow.into_iter().collect(),
            log: Mutex::new(Vec::new()),
        }
    }

    pub fn allows(&self, host: &str) -> bool {
        self.allow.contains(host)
    }

    /// Hand a shared client to an SDK that insists on its own (e.g. atrium's
    /// `ReqwestClient`). Prefer `execute`; the CI sandbox enforces the allowlist
    /// regardless. TODO(net): wrap in a host-enforcing tower middleware so the
    /// in-process guarantee matches the sandbox.
    pub fn client(&self) -> reqwest::Client {
        self.client.clone()
    }

    /// Allowlist-checked send. Logs every attempt (allowed or blocked) for the
    /// trust panel.
    pub async fn execute(&self, req: reqwest::Request) -> Result<reqwest::Response, EgressError> {
        let host = req
            .url()
            .host_str()
            .ok_or(EgressError::NoHost)?
            .to_owned();
        let allowed = self.allows(&host);
        self.log.lock().push(EgressRecord {
            host: host.clone(),
            method: req.method().to_string(),
            allowed,
            at_epoch_secs: now_secs(),
        });
        if !allowed {
            return Err(EgressError::Blocked(host));
        }
        Ok(self.client.execute(req).await?)
    }

    /// Snapshot of the request log (trust-panel data source).
    pub fn log(&self) -> Vec<EgressRecord> {
        self.log.lock().clone()
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

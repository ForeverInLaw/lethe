//! Telegram adapter (M1 integration #3). Stub: descriptor + contract shell.
//! `api_id`/`api_hash` are injected at construction (BYO-first) — never embedded.

use async_trait::async_trait;
use lethe_adapter::{
    AdapterError, Capabilities, ContentType, Descriptor, EnumeratePlan, ItemRef, ItemStream,
    Outcome, PlatformAdapter, PushdownDim, RatePolicy, RiskClass,
};

const CONTENT_TYPES: &[ContentType] = &[ContentType::Dm, ContentType::Media];
const PUSHDOWN: &[PushdownDim] = &[PushdownDim::Scope, PushdownDim::DateRange];

/// Injected app credentials (BYO). No defaults live in this crate.
pub struct ApiCredentials {
    pub api_id: i32,
    pub api_hash: String,
}

pub struct TelegramAdapter {
    descriptor: Descriptor,
    // grammers Client + session; ApiCredentials injected by the app layer.
}

impl TelegramAdapter {
    pub fn new(_creds: ApiCredentials, session_string: &str) -> Self {
        let _ = session_string;
        let descriptor = Descriptor {
            id: "telegram",
            display_name: "Telegram",
            risk_class: RiskClass::Green,
            content_types: CONTENT_TYPES,
            pushdown: PUSHDOWN,
            capabilities: Capabilities { can_redact: false, can_undo: false, batch_delete_max: 100 },
            // Declared so the egress sandbox allowlists the MTProto DCs.
            endpoints: vec![lethe_adapter::Endpoint::host("api.telegram.org")],
        };
        Self { descriptor }
    }
}

#[async_trait]
impl PlatformAdapter for TelegramAdapter {
    fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }
    async fn enumerate(&self, _plan: &EnumeratePlan) -> Result<ItemStream, AdapterError> {
        todo!("iter_messages over dialogs -> ItemStream")
    }
    async fn delete(&self, _items: &[ItemRef]) -> Vec<Outcome> {
        todo!("messages.deleteMessages (revoke=true), 100 ids per call")
    }
    fn rate_policy(&self) -> RatePolicy {
        RatePolicy { max_per_sec: 20.0, max_per_min: Some(300), burst: 20 }
    }
}

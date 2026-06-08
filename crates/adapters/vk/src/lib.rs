//! VK adapter (M1 integration #2). Stub: descriptor + contract shell only.
//! Build out after the Bluesky vertical is proven end-to-end.

use std::sync::Arc;

use async_trait::async_trait;
use lethe_adapter::{
    AdapterError, Capabilities, ContentType, Descriptor, EnumeratePlan, ItemRef, ItemStream,
    Outcome, PlatformAdapter, PushdownDim, RatePolicy, RiskClass,
};
use lethe_net::Egress;

const CONTENT_TYPES: &[ContentType] =
    &[ContentType::Post, ContentType::Comment, ContentType::Reaction, ContentType::Media];
const PUSHDOWN: &[PushdownDim] = &[PushdownDim::ContentType, PushdownDim::Scope];

pub struct VkAdapter {
    egress: Arc<Egress>,
    descriptor: Descriptor,
}

impl VkAdapter {
    pub fn new(egress: Arc<Egress>) -> Self {
        let descriptor = Descriptor {
            id: "vk",
            display_name: "VK",
            risk_class: RiskClass::Green,
            content_types: CONTENT_TYPES,
            pushdown: PUSHDOWN,
            capabilities: Capabilities { can_redact: false, can_undo: false, batch_delete_max: 25 },
            endpoints: vec![lethe_adapter::Endpoint::host("api.vk.com")],
        };
        Self { egress, descriptor }
    }
}

#[async_trait]
impl PlatformAdapter for VkAdapter {
    fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }
    async fn enumerate(&self, _plan: &EnumeratePlan) -> Result<ItemStream, AdapterError> {
        let _ = &self.egress;
        todo!("wall.get / messages.getHistory paginated -> ItemStream")
    }
    async fn delete(&self, _items: &[ItemRef]) -> Vec<Outcome> {
        todo!("execute() batched wall.delete/messages.delete (25 per call)")
    }
    fn rate_policy(&self) -> RatePolicy {
        RatePolicy { max_per_sec: 3.0, max_per_min: None, burst: 3 }
    }
}

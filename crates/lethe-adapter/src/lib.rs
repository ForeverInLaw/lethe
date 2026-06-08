//! The platform contract for Lethe.
//!
//! Outcome-shaped, not transport-shaped: an HTTP adapter and a browser-driving
//! session adapter (M3) satisfy the same traits. Auth is split out of the
//! deletion path because token/auth churn is the #1 maintenance risk.
//!
//! No transport types (reqwest/http) appear in this crate's public API.

use std::collections::BTreeSet;

use async_trait::async_trait;
use futures::stream::BoxStream;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

pub type Result<T> = std::result::Result<T, AdapterError>;

/// Streamed enumeration output. Bounded memory: the pipeline drains this into
/// the SQLite snapshot, never collecting it whole.
pub type ItemStream = BoxStream<'static, Result<Item>>;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("authentication failed: {0}")]
    Auth(String),
    /// Honor exactly: `Retry-After` (HTTP) or `FLOOD_WAIT` (Telegram).
    #[error("rate limited; retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },
    /// Item already gone. The pipeline treats this as success (idempotent resume).
    #[error("item not found (treat as already-deleted)")]
    NotFound,
    #[error("transport error: {0}")]
    Transport(String),
    #[error("platform error: {0}")]
    Platform(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
}

// ---------------------------------------------------------------------------
// Taxonomy
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentType {
    Post,
    Comment,
    Reaction,
    Media,
    Dm,
}

/// Drives FR-TRUST-4: `Red` platforms require a ban-risk opt-in before the
/// first run and are labeled "best-effort / may break".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskClass {
    Green,
    Yellow,
    Red,
}

/// Dimensions an adapter can constrain server-side (cheap pushdown). Everything
/// else (keyword/regex/engagement) is evaluated by the core predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushdownDim {
    ContentType,
    Scope,
    DateRange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeKind {
    Channel,
    Server,
    Board,
    Conversation,
}

#[derive(Debug, Clone)]
pub struct Scope {
    pub kind: ScopeKind,
    pub id: String,
}

// ---------------------------------------------------------------------------
// Descriptor — static identity + capabilities + egress contribution
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Capabilities {
    pub can_redact: bool,
    pub can_undo: bool,
    /// Max items per platform delete call; the adapter chunks internally.
    pub batch_delete_max: usize,
}

/// A host this adapter is permitted to reach. The union across active adapters
/// is the egress allowlist enforced by `lethe-net`.
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub host: String,
}

impl Endpoint {
    pub fn host(h: impl Into<String>) -> Self {
        Self { host: h.into() }
    }
}

#[derive(Debug, Clone)]
pub struct Descriptor {
    pub id: &'static str,
    pub display_name: &'static str,
    pub risk_class: RiskClass,
    pub content_types: &'static [ContentType],
    pub pushdown: &'static [PushdownDim],
    pub capabilities: Capabilities,
    /// May be dynamic (e.g. Telegram DC list), hence owned.
    pub endpoints: Vec<Endpoint>,
}

// ---------------------------------------------------------------------------
// Enumeration plan + items
// ---------------------------------------------------------------------------

/// The pushdown subset core hands to `enumerate` so the adapter fetches less.
/// The full filter predicate is applied by core over the returned stream.
#[derive(Debug, Clone, Default)]
pub struct EnumeratePlan {
    pub content_types: BTreeSet<ContentType>,
    pub scope: Option<Scope>,
    pub date_from: Option<OffsetDateTime>,
    pub date_to: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, Default)]
pub struct Engagement {
    pub likes: Option<u64>,
    pub replies: Option<u64>,
    pub reposts: Option<u64>,
    pub views: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaRef {
    pub url: String,
    pub mime: Option<String>,
}

/// Opaque handle the adapter needs to delete an item. `platform_id` is the
/// stable idempotency key persisted by the store; `token` carries any extra
/// adapter-specific routing (e.g. AT-Proto `collection:rkey`, TG `peer:msg_id`).
#[derive(Debug, Clone)]
pub struct ItemRef {
    pub platform_id: String,
    pub token: Option<String>,
}

/// Enumerated metadata. In-memory only (not serialized here); the store
/// persists its own projection.
#[derive(Debug, Clone)]
pub struct Item {
    pub content_type: ContentType,
    pub created_at: Option<OffsetDateTime>,
    /// Text for keyword/regex predicate (None if not applicable).
    pub text: Option<String>,
    pub engagement: Engagement,
    pub scope_id: Option<String>,
    /// Media to fetch into the encrypted backup before deletion.
    pub media: Vec<MediaRef>,
    pub item_ref: ItemRef,
}

// ---------------------------------------------------------------------------
// Outcomes + rate policy
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum Outcome {
    Deleted,
    Skipped { reason: String },
    Failed { reason: String, retryable: bool },
    RateLimited { retry_after_secs: u64 },
}

/// Base limits the core scheduler seeds its per-account token bucket from
/// (it runs at a conservative fraction of these).
#[derive(Debug, Clone)]
pub struct RatePolicy {
    pub max_per_sec: f64,
    pub max_per_min: Option<u32>,
    pub burst: u32,
}

// ---------------------------------------------------------------------------
// Auth (split out of the adapter)
// ---------------------------------------------------------------------------

/// Opaque credential blob. Stored by core in the OS keychain, never logged.
#[derive(Clone)]
pub struct SecretBlob(pub String);

impl std::fmt::Debug for SecretBlob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretBlob(***redacted***)")
    }
}

#[derive(Debug, Clone)]
pub struct Credential {
    pub account_label: String,
    pub secret: SecretBlob,
}

/// UI callback for interactive auth: app-password / Telegram login code,
/// ban-risk confirmation for `Red` platforms.
#[async_trait]
pub trait Consent: Send + Sync {
    async fn confirm(&self, prompt: &str) -> bool;
    async fn input(&self, prompt: &str, secret: bool) -> Option<String>;
}

#[async_trait]
pub trait AuthProvider: Send + Sync {
    fn platform_id(&self) -> &'static str;
    async fn connect(&self, consent: &dyn Consent) -> Result<Credential>;
    async fn refresh(&self, cred: &Credential) -> Result<Credential>;
    /// Revoke remotely where possible; core wipes the keychain entry after.
    async fn revoke(&self, cred: &Credential) -> Result<()>;
}

// ---------------------------------------------------------------------------
// The adapter
// ---------------------------------------------------------------------------

#[async_trait]
pub trait PlatformAdapter: Send + Sync {
    fn descriptor(&self) -> &Descriptor;

    /// Phase-1 enumeration. Adapter pushes down only the dims it declared in
    /// `descriptor().pushdown`; core applies the rest.
    async fn enumerate(&self, plan: &EnumeratePlan) -> Result<ItemStream>;

    /// Batch delete. The adapter chunks to its platform batch size; the
    /// returned vec is aligned 1:1 with `items`.
    async fn delete(&self, items: &[ItemRef]) -> Vec<Outcome>;

    /// Overwrite-then-delete text (FR-DEL-3), capability-gated.
    async fn redact(&self, _item: &ItemRef, _new_text: &str) -> Outcome {
        Outcome::Failed {
            reason: "redact not supported by this adapter".into(),
            retryable: false,
        }
    }

    fn rate_policy(&self) -> RatePolicy;
}

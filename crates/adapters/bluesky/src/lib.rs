//! Bluesky adapter (M1 tracer) — the thinnest full vertical.
//!
//! atrium entrypoints:
//! - auth   : `AtpAgent::login` (app-password `com.atproto.server.createSession`)
//! - list   : `com.atproto.repo.list_records` (paginated by cursor) for enumerate
//! - delete : `com.atproto.repo.delete_record` (idempotent; "ensure absent")
//!
//! The reqwest client comes from `lethe_net::Egress` so all traffic is on the
//! allowlist: `bsky.social` + the account PDS host. The adapter never builds its
//! own client — that is the zero-egress invariant, structurally.

use std::sync::Arc;

use async_trait::async_trait;
use atrium_api::agent::atp_agent::store::MemorySessionStore;
use atrium_api::agent::atp_agent::{AtpAgent, AtpSession};
use atrium_api::types::string::{AtIdentifier, Nsid, RecordKey};
use atrium_api::types::TryFromUnknown;
use atrium_xrpc_client::reqwest::ReqwestClientBuilder;
use lethe_adapter::{
    AdapterError, AuthProvider, Capabilities, Consent, ContentType, Credential, Descriptor,
    Engagement, EnumeratePlan, Item, ItemRef, ItemStream, Outcome, PlatformAdapter, PushdownDim,
    RatePolicy, Result, RiskClass, SecretBlob,
};
use lethe_net::Egress;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Entryway the agent logs in / resumes against. atrium reconfigures the
/// effective endpoint from the session's DID doc, so this is just the bootstrap
/// host. The real PDS host is still declared in the descriptor (egress allow).
const ENTRYWAY: &str = "https://bsky.social";

type Xrpc = atrium_xrpc_client::reqwest::ReqwestClient;
type Agent = AtpAgent<MemorySessionStore, Xrpc>;

const CONTENT_TYPES: &[ContentType] = &[ContentType::Post, ContentType::Reaction];
// list_records can scope by collection (type) and paginate by date; no
// server-side keyword search.
const PUSHDOWN: &[PushdownDim] = &[PushdownDim::ContentType, PushdownDim::DateRange];

/// AT-Proto record collections we enumerate, one per supported `ContentType`.
const COLLECTION_POST: &str = "app.bsky.feed.post";
const COLLECTION_LIKE: &str = "app.bsky.feed.like";

fn collection_for(ct: ContentType) -> Option<&'static str> {
    match ct {
        ContentType::Post => Some(COLLECTION_POST),
        ContentType::Reaction => Some(COLLECTION_LIKE),
        _ => None,
    }
}

fn content_type_for(collection: &str) -> ContentType {
    match collection {
        COLLECTION_LIKE => ContentType::Reaction,
        _ => ContentType::Post,
    }
}

/// Build an XRPC client pinned to the egress chokepoint. The reqwest client is
/// owned by `Egress`; we only ever borrow a clone of it.
fn build_agent(egress: &Egress) -> Agent {
    let xrpc = ReqwestClientBuilder::new(ENTRYWAY).client(egress.client()).build();
    AtpAgent::new(xrpc, MemorySessionStore::default())
}

/// Map an atrium XRPC error onto our transport-free taxonomy.
fn map_err<E: std::fmt::Display + std::fmt::Debug>(e: atrium_api::xrpc::Error<E>) -> AdapterError {
    if let atrium_api::xrpc::Error::XrpcResponse(ref resp) = e {
        match resp.status.as_u16() {
            429 => return AdapterError::RateLimited { retry_after_secs: 60 },
            404 => return AdapterError::NotFound,
            500..=599 => return AdapterError::Transport(e.to_string()),
            _ => return AdapterError::Platform(e.to_string()),
        }
    }
    AdapterError::Transport(e.to_string())
}

/// The `value` of a feed record, parsed best-effort for the core predicate.
/// Engagement counts are not on the record itself (they need the feed API), so
/// they stay `None` for the tracer.
#[derive(serde::Deserialize)]
struct RecordValue {
    text: Option<String>,
    #[serde(rename = "createdAt")]
    created_at: Option<String>,
}

pub struct BlueskyAdapter {
    agent: Arc<Agent>,
    descriptor: Descriptor,
    /// Authenticated repo (account DID). `None` until `authenticate` runs.
    repo: Option<AtIdentifier>,
}

impl BlueskyAdapter {
    pub fn new(egress: Arc<Egress>, pds_host: &str) -> Self {
        let descriptor = Descriptor {
            id: "bluesky",
            display_name: "Bluesky",
            risk_class: RiskClass::Green,
            content_types: CONTENT_TYPES,
            pushdown: PUSHDOWN,
            capabilities: Capabilities { can_redact: false, can_undo: false, batch_delete_max: 200 },
            endpoints: vec![
                lethe_adapter::Endpoint::host("bsky.social"),
                lethe_adapter::Endpoint::host(pds_host.to_owned()),
            ],
        };
        Self { agent: Arc::new(build_agent(&egress)), descriptor, repo: None }
    }

    /// Restore a stored session so `enumerate`/`delete` act as the account.
    /// Called once, before the adapter is handed to the pipeline.
    pub async fn authenticate(&mut self, cred: &Credential) -> Result<()> {
        let session: AtpSession = serde_json::from_str(&cred.secret.0)
            .map_err(|e| AdapterError::Auth(format!("malformed session blob: {e}")))?;
        let did = session.did.clone();
        self.agent
            .resume_session(session)
            .await
            .map_err(|e| AdapterError::Auth(e.to_string()))?;
        self.repo = Some(AtIdentifier::from(did));
        Ok(())
    }

    fn repo(&self) -> Result<AtIdentifier> {
        self.repo
            .clone()
            .ok_or_else(|| AdapterError::Auth("adapter not authenticated".into()))
    }
}

#[async_trait]
impl PlatformAdapter for BlueskyAdapter {
    fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }

    async fn enumerate(&self, plan: &EnumeratePlan) -> Result<ItemStream> {
        let repo = self.repo()?;
        let agent = self.agent.clone();

        // Which collections to walk: the pushed-down content types, or all
        // supported ones when the plan does not constrain type.
        let collections: Vec<&'static str> = if plan.content_types.is_empty() {
            vec![COLLECTION_POST, COLLECTION_LIKE]
        } else {
            plan.content_types.iter().copied().filter_map(collection_for).collect()
        };

        let stream = async_stream::try_stream! {
            for collection in collections {
                let nsid = Nsid::new(collection.to_owned())
                    .map_err(|e| AdapterError::Platform(format!("bad collection nsid: {e}")))?;
                let ct = content_type_for(collection);
                let mut cursor: Option<String> = None;

                loop {
                    let params = atrium_api::com::atproto::repo::list_records::ParametersData {
                        collection: nsid.clone(),
                        cursor: cursor.clone(),
                        limit: None,
                        repo: repo.clone(),
                        reverse: None,
                    };
                    let out = agent
                        .api
                        .com
                        .atproto
                        .repo
                        .list_records(params.into())
                        .await
                        .map_err(map_err)?;

                    for rec in &out.records {
                        yield record_to_item(rec, collection, ct);
                    }

                    cursor = out.cursor.clone();
                    if cursor.is_none() {
                        break;
                    }
                }
            }
        };

        Ok(Box::pin(stream))
    }

    async fn delete(&self, items: &[ItemRef]) -> Vec<Outcome> {
        let repo = match self.repo() {
            Ok(r) => r,
            Err(e) => return items.iter().map(|_| failed(e.to_string(), false)).collect(),
        };

        // deleteRecord is idempotent server-side ("delete, or ensure it doesn't
        // exist"), so an already-gone record returns Ok — resume is safe.
        // Debt: switch to applyWrites for true batching (batch_delete_max).
        let mut outcomes = Vec::with_capacity(items.len());
        for item in items {
            outcomes.push(self.delete_one(&repo, item).await);
        }
        outcomes
    }

    fn rate_policy(&self) -> RatePolicy {
        // Bluesky is generous; stay conservative anyway.
        RatePolicy { max_per_sec: 8.0, max_per_min: None, burst: 8 }
    }
}

impl BlueskyAdapter {
    async fn delete_one(&self, repo: &AtIdentifier, item: &ItemRef) -> Outcome {
        let Some((collection, rkey)) = item.token.as_deref().and_then(|t| t.split_once(':')) else {
            return failed(format!("item {} has no collection:rkey token", item.platform_id), false);
        };
        let collection = match Nsid::new(collection.to_owned()) {
            Ok(n) => n,
            Err(e) => return failed(format!("bad collection: {e}"), false),
        };
        let rkey = match RecordKey::new(rkey.to_owned()) {
            Ok(k) => k,
            Err(e) => return failed(format!("bad rkey: {e}"), false),
        };

        let input = atrium_api::com::atproto::repo::delete_record::InputData {
            collection,
            repo: repo.clone(),
            rkey,
            swap_commit: None,
            swap_record: None,
        };

        match self.agent.api.com.atproto.repo.delete_record(input.into()).await {
            Ok(_) => Outcome::Deleted,
            Err(e) => match map_err(e) {
                AdapterError::NotFound => Outcome::Deleted,
                AdapterError::RateLimited { retry_after_secs } => {
                    Outcome::RateLimited { retry_after_secs }
                }
                AdapterError::Transport(m) => failed(m, true),
                other => failed(other.to_string(), false),
            },
        }
    }
}

fn failed(reason: String, retryable: bool) -> Outcome {
    Outcome::Failed { reason, retryable }
}

/// Map one list_records record to a core `Item`. `uri` is the idempotency key;
/// `token = "collection:rkey"` is what `delete` needs.
fn record_to_item(
    rec: &atrium_api::com::atproto::repo::list_records::Record,
    collection: &str,
    content_type: ContentType,
) -> Item {
    let rkey = rec.uri.rsplit('/').next().unwrap_or_default();
    let parsed = RecordValue::try_from_unknown(rec.value.clone()).ok();
    let (text, created_at) = match parsed {
        Some(v) => {
            let ts = v
                .created_at
                .as_deref()
                .and_then(|s| OffsetDateTime::parse(s, &Rfc3339).ok());
            (v.text, ts)
        }
        None => (None, None),
    };

    Item {
        content_type,
        created_at,
        text,
        engagement: Engagement::default(),
        scope_id: None,
        media: Vec::new(),
        item_ref: ItemRef {
            platform_id: rec.uri.clone(),
            token: Some(format!("{collection}:{rkey}")),
        },
    }
}

/// App-password auth (tracer). Debt: replace with DPoP OAuth before ship.
pub struct BlueskyAuth {
    egress: Arc<Egress>,
}

impl BlueskyAuth {
    pub fn new(egress: Arc<Egress>) -> Self {
        Self { egress }
    }
}

#[async_trait]
impl AuthProvider for BlueskyAuth {
    fn platform_id(&self) -> &'static str {
        "bluesky"
    }

    async fn connect(&self, consent: &dyn Consent) -> Result<Credential> {
        let identifier = consent
            .input("Bluesky handle or email", false)
            .await
            .ok_or_else(|| AdapterError::Auth("no identifier provided".into()))?;
        let password = consent
            .input("Bluesky app password", true)
            .await
            .ok_or_else(|| AdapterError::Auth("no app password provided".into()))?;

        let agent = build_agent(&self.egress);
        agent
            .login(&identifier, &password)
            .await
            .map_err(|e| AdapterError::Auth(e.to_string()))?;
        let session = agent
            .get_session()
            .await
            .ok_or_else(|| AdapterError::Auth("login returned no session".into()))?;
        let blob = serde_json::to_string(&session)
            .map_err(|e| AdapterError::Transport(e.to_string()))?;

        Ok(Credential { account_label: identifier, secret: SecretBlob(blob) })
    }

    async fn refresh(&self, cred: &Credential) -> Result<Credential> {
        // atrium refreshes the access token lazily on the next API call; here we
        // just re-validate and re-serialize whatever session is current.
        let session: AtpSession = serde_json::from_str(&cred.secret.0)
            .map_err(|e| AdapterError::Auth(format!("malformed session blob: {e}")))?;
        let agent = build_agent(&self.egress);
        agent
            .resume_session(session)
            .await
            .map_err(|e| AdapterError::Auth(e.to_string()))?;
        let session = agent
            .get_session()
            .await
            .ok_or_else(|| AdapterError::Auth("session lost after resume".into()))?;
        let blob = serde_json::to_string(&session)
            .map_err(|e| AdapterError::Transport(e.to_string()))?;
        Ok(Credential { account_label: cred.account_label.clone(), secret: SecretBlob(blob) })
    }

    async fn revoke(&self, cred: &Credential) -> Result<()> {
        // Best-effort remote revoke; core wipes the keychain entry after.
        let session: AtpSession = serde_json::from_str(&cred.secret.0)
            .map_err(|e| AdapterError::Auth(format!("malformed session blob: {e}")))?;
        let agent = build_agent(&self.egress);
        if agent.resume_session(session).await.is_ok() {
            let _ = agent.api.com.atproto.server.delete_session().await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter() -> BlueskyAdapter {
        BlueskyAdapter::new(Arc::new(Egress::new(std::iter::empty::<String>())), "bsky.social")
    }

    #[test]
    fn descriptor_declares_egress_hosts() {
        let a = adapter();
        let hosts: Vec<_> = a.descriptor().endpoints.iter().map(|e| e.host.as_str()).collect();
        assert!(hosts.contains(&"bsky.social"));
    }

    #[tokio::test]
    async fn enumerate_without_auth_is_rejected() {
        let a = adapter();
        let err = a.enumerate(&EnumeratePlan::default()).await.err().expect("must error");
        assert!(matches!(err, AdapterError::Auth(_)));
    }

    #[tokio::test]
    async fn delete_without_auth_fails_every_item() {
        let a = adapter();
        let items = vec![ItemRef { platform_id: "at://x/app.bsky.feed.post/1".into(), token: Some("app.bsky.feed.post:1".into()) }];
        let out = a.delete(&items).await;
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], Outcome::Failed { retryable: false, .. }));
    }
}

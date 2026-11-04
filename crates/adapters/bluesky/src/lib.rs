//! Bluesky adapter (M1 tracer) — the thinnest full vertical.
//!
//! atrium entrypoints:
//! - auth   : `AtpAgent::login` (app-password `com.atproto.server.createSession`)
//! - list   : `com.atproto.repo.list_records` (paginated by cursor) for enumerate
//! - fetch  : `com.atproto.sync.get_blob` for a post's files, whole and in memory
//! - delete : `com.atproto.repo.delete_record` (idempotent; "ensure absent")
//!
//! The reqwest client comes from `lethe_net::Egress` so all traffic is on the
//! allowlist: `bsky.social` + the account PDS host. The adapter never builds its
//! own client — that is the zero-egress invariant, structurally.

use std::future::Future;
use std::io::Write;
use std::path::PathBuf;
use std::pin::pin;
use std::sync::Arc;

use async_trait::async_trait;
use futures::future::{self, BoxFuture, Either};
use atrium_api::agent::Configure;
use atrium_api::agent::atp_agent::store::MemorySessionStore;
use atrium_api::agent::atp_agent::{AtpAgent, AtpSession};
use atrium_api::types::string::{AtIdentifier, Cid, Did, Nsid, RecordKey};
use atrium_api::types::{BlobRef, TryFromUnknown, TypedBlobRef, Unknown};
use atrium_xrpc_client::reqwest::ReqwestClientBuilder;
use lethe_adapter::{
    AdapterError, AuthProvider, Capabilities, Consent, ContentType, Credential, DeleteReach, Descriptor,
    Engagement, EnumeratePlan, FetchedMedia, Item, ItemRef, ItemStream, MediaRef, Outcome,
    PlatformAdapter, PlatformRecord, PushdownDim,
    RatePolicy, Result, RiskClass, SecretBlob,
};
use lethe_net::Egress;
use serde::Deserialize;
use sha2::{Digest, Sha256};
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

/// A sign-in or a session resume the server refuses means the credentials no longer
/// work; no answer, a server fault or a rate limit says nothing about them.
fn sign_in_error<E: std::fmt::Display + std::fmt::Debug>(e: atrium_api::xrpc::Error<E>) -> AdapterError {
    match map_err(e) {
        AdapterError::Platform(message) => AdapterError::Auth(message),
        AdapterError::NotFound => AdapterError::Auth("the server has no such account".into()),
        other => other,
    }
}

/// The file is gone, but the post may not be: core must not count it as deleted. Only
/// the PDS naming this blob or repo as unavailable is a refusal; an expired session
/// comes back as a 400 or 401 too, and says nothing about the file.
fn map_blob_error(
    e: atrium_api::xrpc::Error<atrium_api::com::atproto::sync::get_blob::Error>,
) -> AdapterError {
    if let atrium_api::xrpc::Error::XrpcResponse(ref resp) = e {
        if matches!(resp.error, Some(atrium_api::xrpc::error::XrpcErrorKind::Custom(_))) {
            return AdapterError::FileRefused(e.to_string());
        }
    }
    match map_err(e) {
        AdapterError::NotFound => AdapterError::FileRefused("the PDS no longer has this file".into()),
        other => other,
    }
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
    /// Authenticated account. `None` until `authenticate` runs.
    did: Option<Did>,
    /// Where a downloaded file waits, unencrypted, until the backup has it.
    downloads: PathBuf,
    /// Completes once the run is stopped, calling off a download in flight.
    stop: Arc<dyn Fn() -> BoxFuture<'static, ()> + Send + Sync>,
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
        Self {
            agent: Arc::new(build_agent(&egress)),
            descriptor,
            did: None,
            downloads: std::env::temp_dir(),
            stop: Arc::new(|| Box::pin(future::pending())),
        }
    }

    /// Calls off a download once a future from `stop` completes, so stopping a run
    /// does not wait for a large file to arrive. Without it a download runs to its end.
    pub fn stopped_by<F>(mut self, stop: impl Fn() -> F + Send + Sync + 'static) -> Self
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.stop = Arc::new(move || Box::pin(stop()));
        self
    }

    /// Downloads files into `dir` instead of the system temp directory. A file sits
    /// there unencrypted until the backup has it, and stays if the process dies
    /// first, so `dir` should be one the caller empties on startup.
    pub fn download_to(mut self, dir: PathBuf) -> Self {
        self.downloads = dir;
        self
    }

    /// Restore a stored session so `enumerate`/`fetch_media`/`delete` act as the account.
    /// Called once, before the adapter is handed to the pipeline.
    pub async fn authenticate(&mut self, cred: &Credential) -> Result<()> {
        let session: AtpSession = serde_json::from_str(&cred.secret.0)
            .map_err(|e| AdapterError::Auth(format!("malformed session blob: {e}")))?;
        let did = session.did.clone();
        self.agent
            .resume_session(session)
            .await
            .map_err(sign_in_error)?;
        self.did = Some(did);
        Ok(())
    }

    fn did(&self) -> Result<Did> {
        self.did
            .clone()
            .ok_or_else(|| AdapterError::Auth("adapter not authenticated".into()))
    }

    fn repo(&self) -> Result<AtIdentifier> {
        self.did().map(AtIdentifier::from)
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
                        yield record_to_item(rec, collection, ct)?;
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

    async fn fetch_media(&self, _item: &ItemRef, media: &MediaRef) -> Result<FetchedMedia> {
        let cid: Cid = media
            .url
            .parse()
            .map_err(|e| AdapterError::Platform(format!("bad blob cid: {e}")))?;
        let did = self.did()?;
        let expected = cid.clone();
        let params = atrium_api::com::atproto::sync::get_blob::ParametersData { cid, did };
        let download = self.agent.api.com.atproto.sync.get_blob(params.into());
        // Nothing is on disk until the whole file has arrived, so dropping it leaves nothing.
        let bytes = match future::select(pin!(download), (self.stop)()).await {
            Either::Left((bytes, _)) => bytes.map_err(map_blob_error)?,
            Either::Right(((), _)) => return Err(AdapterError::Transport("the run was stopped".into())),
        };
        if !is_content_of(&bytes, &expected) {
            return Err(AdapterError::Transport(
                "the downloaded file does not match the post".into(),
            ));
        }

        let mut file = tempfile::NamedTempFile::new_in(&self.downloads).map_err(io_error)?;
        file.write_all(&bytes).map_err(io_error)?;
        let path = file.into_temp_path().keep().map_err(|e| io_error(e.error))?;
        Ok(FetchedMedia { path, handle: 0 })
    }

    /// Any answer from the PDS, a refusal included, means it is there. A server fault
    /// counts as down, like a network error: the run waits rather than failing files.
    async fn is_reachable(&self) -> bool {
        let answer = self.agent.api.com.atproto.server.describe_server().await;
        !matches!(answer.map_err(map_err), Err(AdapterError::Transport(_)))
    }

    async fn release_media(&self, file: &FetchedMedia) -> Result<()> {
        tokio::fs::remove_file(&file.path).await.map_err(io_error)
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

/// A blob's CID is the SHA-256 of its bytes, so a post is only deleted once the
/// backup holds exactly what it referenced.
fn is_content_of(bytes: &[u8], cid: &Cid) -> bool {
    const SHA2_256: u64 = 0x12;
    let hash = cid.as_ref().hash();
    hash.code() == SHA2_256 && hash.digest() == Sha256::digest(bytes).as_slice()
}

fn io_error(error: std::io::Error) -> AdapterError {
    AdapterError::Platform(format!("downloaded file: {error}"))
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
) -> Result<Item> {
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

    let files = record_files(&rec.value)?;
    Ok(Item {
        content_type,
        subtype: None,
        created_at,
        text,
        engagement: Engagement::default(),
        scope_id: None,
        media: files.media,
        platform_record: Some(PlatformRecord::capture(rec)?),
        backup_gap: files
            .has_unreadable_blob
            .then(|| "a file in this post has a reference that cannot be read".to_owned()),
        delete_reach: DeleteReach::Everyone,
        item_ref: ItemRef {
            platform_id: rec.uri.clone(),
            token: Some(format!("{collection}:{rkey}")),
        },
    })
}

#[derive(Default)]
struct RecordFiles {
    media: Vec<MediaRef>,
    has_unreadable_blob: bool,
}

/// Every blob a record owns, wherever it sits: images, a video and its captions,
/// a link card's thumbnail, embed types added after this was written. A quoted
/// post is only a reference, so its files are not picked up. A post listed without
/// its files would be deleted without them, so failing to read a record ends the scan.
fn record_files(record: &Unknown) -> Result<RecordFiles> {
    let record = serde_json::to_value(record)
        .map_err(|e| AdapterError::Platform(format!("unreadable record: {e}")))?;
    let mut files = RecordFiles::default();
    collect_blobs(&record, &mut files);
    Ok(files)
}

fn collect_blobs(value: &serde_json::Value, files: &mut RecordFiles) {
    if let Ok(blob) = BlobRef::deserialize(value) {
        files.media.push(blob_media(blob));
        return;
    }
    if value.get("$type").and_then(serde_json::Value::as_str) == Some("blob") {
        files.has_unreadable_blob = true;
        return;
    }
    match value {
        serde_json::Value::Object(fields) => {
            fields.values().for_each(|field| collect_blobs(field, files));
        }
        serde_json::Value::Array(values) => {
            values.iter().for_each(|value| collect_blobs(value, files));
        }
        _ => {}
    }
}

/// `MediaRef.url` holds the blob's CID. Records from before blobs were typed state
/// no size.
fn blob_media(blob: BlobRef) -> MediaRef {
    let (cid, mime, size) = match blob {
        BlobRef::Typed(TypedBlobRef::Blob(blob)) => {
            (blob.r#ref.0.to_string(), blob.mime_type, Some(blob.size as u64))
        }
        BlobRef::Untyped(blob) => (blob.cid, blob.mime_type, None),
    };
    MediaRef { url: cid, mime: Some(mime), file_name: None, size }
}

/// App-password auth (tracer). Debt: replace with DPoP OAuth before ship.
pub struct BlueskyAuth {
    egress: Arc<Egress>,
    entryway: String,
}

impl BlueskyAuth {
    pub fn new(egress: Arc<Egress>) -> Self {
        Self { egress, entryway: ENTRYWAY.into() }
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
        agent.configure_endpoint(self.entryway.clone());
        agent.login(&identifier, &password).await.map_err(sign_in_error)?;
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
            .map_err(sign_in_error)?;
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
    use serde_json::json;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn adapter() -> BlueskyAdapter {
        BlueskyAdapter::new(Arc::new(Egress::new(std::iter::empty::<String>())), "bsky.social")
    }

    #[test]
    fn descriptor_declares_egress_hosts() {
        let a = adapter();
        let hosts: Vec<_> = a.descriptor().endpoints.iter().map(|e| e.host.as_str()).collect();
        assert!(hosts.contains(&"bsky.social"));
    }

    const POST: &str = "at://did:plc:test/app.bsky.feed.post/1";
    const IMAGE_ONE: &str = "bafkreifyopgoazxlalw3rdmlxmdkfnj75f5rjwj3pl2d7chvyvyhfjqzaq";
    const IMAGE_TWO: &str = "bafkreifhmhch3in53b7vsjkmpodmptqp7tdgvuhaalbpkjxk4i5coqdwdy";
    const VIDEO: &str = "bafkreiamvmojmf2aj6xswjhcehqytssziwat4fgt65tdiwyjzij3xyup7q";
    const CAPTIONS: &str = "bafkreig4wpxo2dzlsen3mfpuob6d7jwxovre3dzmh5gmm2jev656pfdcgq";
    const THUMB: &str = "bafkreiaf53wc24eek2knhoujvwpbynfwwtmamj24hrr3qqsbuqfoiwi4uq";
    const LEGACY: &str = "bafkreiget7vhijp2p6djtcl2s7avtrtjajt5sab3w6gfh6x2r7avyms5qq";

    fn blob(cid: &str, mime: &str, size: u64) -> serde_json::Value {
        json!({ "$type": "blob", "ref": { "$link": cid }, "mimeType": mime, "size": size })
    }

    /// Media of a post whose record holds `embed`, as `list_records` returns it.
    fn media_of(embed: serde_json::Value) -> Vec<MediaRef> {
        item_of(embed).media
    }

    fn item_of(embed: serde_json::Value) -> Item {
        let record = serde_json::from_value(json!({
            "uri": POST,
            "cid": IMAGE_ONE,
            "value": {
                "$type": "app.bsky.feed.post",
                "text": "hello",
                "createdAt": "2026-01-01T00:00:00.000Z",
                "embed": embed,
            },
        }))
        .unwrap();
        record_to_item(&record, COLLECTION_POST, ContentType::Post).unwrap()
    }

    fn media(cid: &str, mime: &str, size: Option<u64>) -> MediaRef {
        MediaRef { url: cid.into(), mime: Some(mime.into()), file_name: None, size }
    }

    #[test]
    fn a_post_lists_its_images() {
        let found = media_of(json!({
            "$type": "app.bsky.embed.images",
            "images": [
                { "alt": "one", "image": blob(IMAGE_ONE, "image/jpeg", 100) },
                { "alt": "two", "image": blob(IMAGE_TWO, "image/png", 200) },
            ],
        }));
        assert_eq!(
            found,
            [
                media(IMAGE_ONE, "image/jpeg", Some(100)),
                media(IMAGE_TWO, "image/png", Some(200)),
            ]
        );
    }

    #[test]
    fn a_post_lists_its_video_and_captions() {
        let found = media_of(json!({
            "$type": "app.bsky.embed.video",
            "video": blob(VIDEO, "video/mp4", 300),
            "captions": [{ "lang": "en", "file": blob(CAPTIONS, "text/vtt", 40) }],
        }));
        assert_eq!(found.len(), 2);
        assert!(found.contains(&media(VIDEO, "video/mp4", Some(300))));
        assert!(found.contains(&media(CAPTIONS, "text/vtt", Some(40))));
    }

    #[test]
    fn a_quote_post_lists_its_own_media_but_not_the_quoted_post() {
        let found = media_of(json!({
            "$type": "app.bsky.embed.recordWithMedia",
            "record": {
                "$type": "app.bsky.embed.record",
                "record": { "uri": "at://did:plc:other/app.bsky.feed.post/2", "cid": IMAGE_TWO },
            },
            "media": {
                "$type": "app.bsky.embed.images",
                "images": [{ "alt": "", "image": blob(IMAGE_ONE, "image/jpeg", 100) }],
            },
        }));
        assert_eq!(found, [media(IMAGE_ONE, "image/jpeg", Some(100))]);
    }

    #[test]
    fn a_link_card_lists_its_thumbnail() {
        let found = media_of(json!({
            "$type": "app.bsky.embed.external",
            "external": {
                "uri": "https://example.com",
                "title": "t",
                "description": "d",
                "thumb": blob(THUMB, "image/webp", 50),
            },
        }));
        assert_eq!(found, [media(THUMB, "image/webp", Some(50))]);
    }

    #[test]
    fn a_blob_in_an_old_untyped_record_has_no_size() {
        let found = media_of(json!({
            "$type": "app.bsky.embed.images",
            "images": [{ "alt": "", "image": { "cid": LEGACY, "mimeType": "image/jpeg" } }],
        }));
        assert_eq!(found, [media(LEGACY, "image/jpeg", None)]);
    }

    #[test]
    fn an_embed_type_nobody_knows_yet_still_gives_up_its_files() {
        let found = media_of(json!({
            "$type": "app.bsky.embed.somethingNew",
            "gallery": { "cover": blob(IMAGE_ONE, "image/avif", 70) },
        }));
        assert_eq!(found, [media(IMAGE_ONE, "image/avif", Some(70))]);
    }

    #[test]
    fn a_quote_without_media_lists_nothing() {
        let found = media_of(json!({
            "$type": "app.bsky.embed.record",
            "record": { "uri": "at://did:plc:other/app.bsky.feed.post/2", "cid": IMAGE_TWO },
        }));
        assert!(found.is_empty());
    }

    fn post_ref() -> ItemRef {
        ItemRef { platform_id: POST.into(), token: Some("app.bsky.feed.post:1".into()) }
    }

    /// An adapter signed in to `did:plc:test` on a fake PDS answering getBlob with `reply`.
    async fn adapter_on_pds(reply: ResponseTemplate) -> (BlueskyAdapter, MockServer) {
        let pds = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/xrpc/com.atproto.sync.getBlob"))
            .and(query_param("did", "did:plc:test"))
            .and(query_param("cid", IMAGE_ONE))
            .respond_with(reply)
            .mount(&pds)
            .await;
        let mut a = adapter();
        a.agent.configure_endpoint(pds.uri());
        a.did = Some("did:plc:test".parse().unwrap());
        (a, pds)
    }

    /// `IMAGE_ONE` is the content address of exactly these bytes.
    fn image_one_reply() -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_raw(b"image one".to_vec(), "image/jpeg")
    }

    async fn fetch_image_one(a: &BlueskyAdapter) -> Result<FetchedMedia> {
        a.fetch_media(&post_ref(), &media(IMAGE_ONE, "image/jpeg", Some(9))).await
    }

    #[tokio::test]
    async fn a_fetched_blob_is_on_disk_in_full() {
        let (a, _pds) = adapter_on_pds(image_one_reply()).await;

        let file = fetch_image_one(&a).await.unwrap();

        assert_eq!(std::fs::read(&file.path).unwrap(), b"image one");
        a.release_media(&file).await.unwrap();
    }

    #[tokio::test]
    async fn a_released_blob_is_gone_from_disk() {
        let (a, _pds) = adapter_on_pds(image_one_reply()).await;
        let file = fetch_image_one(&a).await.unwrap();

        a.release_media(&file).await.unwrap();

        assert!(!file.path.exists());
    }

    #[tokio::test]
    async fn bytes_that_do_not_match_the_cid_are_an_error() {
        // Same length as the real file, so a size check alone would pass it.
        let reply = ResponseTemplate::new(200).set_body_raw(b"image two".to_vec(), "image/jpeg");
        let (a, _pds) = adapter_on_pds(reply).await;

        let error = fetch_image_one(&a).await.unwrap_err();

        assert!(matches!(error, AdapterError::Transport(_)), "{error}");
    }

    #[tokio::test]
    async fn wrong_bytes_are_caught_on_an_old_blob_with_no_size() {
        let reply = ResponseTemplate::new(200).set_body_raw(b"an error page".to_vec(), "text/html");
        let (a, _pds) = adapter_on_pds(reply).await;

        let error = a
            .fetch_media(&post_ref(), &media(IMAGE_ONE, "image/jpeg", None))
            .await
            .unwrap_err();

        assert!(matches!(error, AdapterError::Transport(_)), "{error}");
    }

    #[tokio::test]
    async fn a_blob_the_pds_lost_does_not_read_as_a_deleted_post() {
        let (a, _pds) = adapter_on_pds(ResponseTemplate::new(404)).await;

        let error = fetch_image_one(&a).await.unwrap_err();

        assert!(matches!(error, AdapterError::FileRefused(_)), "{error}");
    }

    #[tokio::test]
    async fn the_pds_naming_a_blob_as_missing_is_a_refusal() {
        let reply = ResponseTemplate::new(400)
            .set_body_json(serde_json::json!({ "error": "BlobNotFound", "message": "Blob not found" }));
        let (a, _pds) = adapter_on_pds(reply).await;

        let error = fetch_image_one(&a).await.unwrap_err();

        assert!(matches!(error, AdapterError::FileRefused(_)), "{error}");
    }

    #[tokio::test]
    async fn an_expired_session_is_not_a_refusal() {
        let expired = ResponseTemplate::new(400)
            .set_body_json(serde_json::json!({ "error": "ExpiredToken", "message": "Token has expired" }));
        for reply in [expired, ResponseTemplate::new(401)] {
            let (a, _pds) = adapter_on_pds(reply).await;

            let error = fetch_image_one(&a).await.unwrap_err();

            assert!(!matches!(error, AdapterError::FileRefused(_)), "{error}");
        }
    }

    #[tokio::test]
    async fn a_stopped_run_calls_off_a_download_in_flight() {
        let slow = image_one_reply().set_delay(std::time::Duration::from_secs(30));
        let (a, _pds) = adapter_on_pds(slow).await;
        let a = a.stopped_by(|| tokio::time::sleep(std::time::Duration::from_millis(100)));

        let fetched = tokio::time::timeout(std::time::Duration::from_secs(5), fetch_image_one(&a)).await;

        let error = fetched.expect("the download outlived the stop").unwrap_err();
        assert!(matches!(error, AdapterError::Transport(_)), "{error}");
    }

    #[tokio::test]
    async fn a_rate_limited_download_says_so() {
        let (a, _pds) = adapter_on_pds(ResponseTemplate::new(429)).await;

        let error = fetch_image_one(&a).await.unwrap_err();

        assert!(matches!(error, AdapterError::RateLimited { .. }), "{error}");
    }

    #[test]
    fn a_post_with_a_broken_blob_reference_says_what_the_backup_lacks() {
        for broken in [
            json!({ "$type": "blob", "ref": { "$link": IMAGE_ONE }, "mimeType": "image/jpeg" }),
            json!({ "$type": "blob", "ref": { "$link": "not a cid" }, "mimeType": "image/jpeg", "size": 9 }),
            json!({ "$type": "blob", "ref": { "$link": IMAGE_ONE }, "mimeType": "image/jpeg", "size": -1 }),
        ] {
            let item = item_of(json!({
                "$type": "app.bsky.embed.images",
                "images": [
                    { "alt": "", "image": broken },
                    { "alt": "", "image": blob(IMAGE_TWO, "image/png", 200) },
                ],
            }));
            assert!(item.backup_gap.is_some());
            assert_eq!(item.media, [media(IMAGE_TWO, "image/png", Some(200))]);
        }
    }

    #[test]
    fn a_whole_post_has_nothing_missing_from_its_backup() {
        let item = item_of(json!({
            "$type": "app.bsky.embed.images",
            "images": [{ "alt": "", "image": blob(IMAGE_ONE, "image/jpeg", 100) }],
        }));
        assert_eq!(item.backup_gap, None);
    }

    #[test]
    fn the_backup_keeps_everything_the_person_wrote_in_a_post() {
        let record = serde_json::from_value(json!({
            "uri": POST,
            "cid": IMAGE_ONE,
            "value": {
                "$type": "app.bsky.feed.post",
                "text": "see this",
                "createdAt": "2026-01-01T00:00:00.000Z",
                "langs": ["en"],
                "reply": {
                    "root": { "uri": "at://did:plc:a/app.bsky.feed.post/root", "cid": IMAGE_ONE },
                    "parent": { "uri": "at://did:plc:a/app.bsky.feed.post/parent", "cid": IMAGE_ONE },
                },
                "facets": [{
                    "index": { "byteStart": 4, "byteEnd": 8 },
                    "features": [{ "$type": "app.bsky.richtext.facet#link", "uri": "https://example.org/a" }],
                }],
                "embed": {
                    "$type": "app.bsky.embed.recordWithMedia",
                    "record": {
                        "$type": "app.bsky.embed.record",
                        "record": { "uri": "at://did:plc:a/app.bsky.feed.post/quoted", "cid": IMAGE_ONE },
                    },
                    "media": {
                        "$type": "app.bsky.embed.images",
                        "images": [{ "alt": "a red door", "image": blob(IMAGE_ONE, "image/jpeg", 100) }],
                    },
                },
            },
        }))
        .unwrap();

        let item = record_to_item(&record, COLLECTION_POST, ContentType::Post).unwrap();
        let kept: serde_json::Value =
            serde_json::from_str(item.platform_record.unwrap().as_json()).unwrap();

        let post = &kept["value"];
        assert_eq!(kept["uri"], POST);
        assert_eq!(post["langs"][0], "en");
        assert_eq!(post["reply"]["parent"]["uri"], "at://did:plc:a/app.bsky.feed.post/parent");
        assert_eq!(post["facets"][0]["features"][0]["uri"], "https://example.org/a");
        assert_eq!(post["facets"][0]["index"]["byteEnd"], 8);
        assert_eq!(post["embed"]["record"]["record"]["uri"], "at://did:plc:a/app.bsky.feed.post/quoted");
        assert_eq!(post["embed"]["media"]["images"][0]["alt"], "a red door");
        assert_eq!(post["embed"]["media"]["images"][0]["image"]["ref"]["$link"], IMAGE_ONE);
    }

    #[test]
    fn the_backup_keeps_a_link_cards_address_and_title() {
        let item = item_of(json!({
            "$type": "app.bsky.embed.external",
            "external": { "uri": "https://example.org/a", "title": "A title", "description": "About it" },
        }));
        let kept: serde_json::Value =
            serde_json::from_str(item.platform_record.unwrap().as_json()).unwrap();

        let card = &kept["value"]["embed"]["external"];
        assert_eq!(card["uri"], "https://example.org/a");
        assert_eq!(card["title"], "A title");
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

    /// Answers the sign-in form with a handle and an app password.
    struct Form;

    #[async_trait]
    impl Consent for Form {
        async fn confirm(&self, _prompt: &str) -> bool {
            true
        }
        async fn input(&self, _prompt: &str, secret: bool) -> Option<String> {
            Some(if secret { "app-password" } else { "alice.test" }.into())
        }
    }

    async fn sign_in_at(entryway: String) -> AdapterError {
        let auth = BlueskyAuth { egress: Arc::new(Egress::new(std::iter::empty::<String>())), entryway };
        auth.connect(&Form).await.unwrap_err()
    }

    async fn sign_in_answered_with(reply: ResponseTemplate) -> AdapterError {
        let entryway = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/xrpc/com.atproto.server.createSession"))
            .respond_with(reply)
            .mount(&entryway)
            .await;
        sign_in_at(entryway.uri()).await
    }

    #[tokio::test]
    async fn a_wrong_app_password_is_a_refused_sign_in() {
        let reply = ResponseTemplate::new(401)
            .set_body_json(json!({ "error": "AuthenticationRequired", "message": "Invalid identifier or password" }));

        let error = sign_in_answered_with(reply).await;

        assert!(matches!(error, AdapterError::Auth(_)), "{error}");
    }

    #[tokio::test]
    async fn a_sign_in_without_network_is_not_a_wrong_password() {
        let error = sign_in_at("http://127.0.0.1:1".into()).await;

        assert!(matches!(error, AdapterError::Transport(_)), "{error}");
    }

    #[tokio::test]
    async fn too_many_sign_ins_ask_to_wait() {
        let error = sign_in_answered_with(ResponseTemplate::new(429)).await;

        assert!(matches!(error, AdapterError::RateLimited { .. }), "{error}");
    }
}

//! Narrow TDLib boundary for Telegram chat-scope discovery and deletion calls.
//!
//! This module is feature-gated so the default workspace build does not require
//! native TDLib. Use `tdlib-docs` with `cargo check` to type-check generated
//! TDLib bindings; test binaries still need native tdjson symbols.

use lethe_adapter::{AdapterError, FetchedMedia, MediaRef};
use tdlib_rs::{enums, functions, types};

const CHAT_LOAD_PAGE: i32 = 100;
const MAX_CHATS: i32 = 100_000;
/// TDLib's download priority range is 1 to 32; nothing else competes in a run.
const DOWNLOAD_PRIORITY: i32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TdlibClientId(i32);

impl TdlibClientId {
    pub fn new(raw: i32) -> Self {
        Self(raw)
    }

    pub fn raw(self) -> i32 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelegramChatKind {
    Private,
    Group,
    Channel,
    Secret,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelegramCleanability {
    DeleteForEveryone,
    OnlyForSelf,
    NotCleanable,
}

impl TelegramCleanability {
    fn from_flags(can_delete_for_all_users: bool, can_delete_only_for_self: bool) -> Self {
        if can_delete_for_all_users {
            Self::DeleteForEveryone
        } else if can_delete_only_for_self {
            Self::OnlyForSelf
        } else {
            Self::NotCleanable
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelegramChatScope {
    pub id: i64,
    pub title: String,
    pub kind: TelegramChatKind,
    pub can_delete_for_all_users: bool,
    pub can_delete_only_for_self: bool,
    pub cleanability: TelegramCleanability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelegramMessageKind {
    Text,
    Media,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelegramMessageRef {
    pub chat_id: i64,
    pub message_id: i64,
    pub sent_at_epoch_secs: i32,
    pub kind: TelegramMessageKind,
    /// Message text or media caption, kept in the backup with the message.
    pub text: Option<String>,
    pub media: Vec<MediaRef>,
}

/// One page of the user's own messages in a chat, newest first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnMessagePage {
    pub messages: Vec<TelegramMessageRef>,
    /// Pass back as `from_message_id` for the next page; 0 means no more results.
    pub next_from_message_id: i64,
    /// Approximate total across all pages; -1 if TDLib does not know it.
    pub total_count: i32,
}

/// Loads a chat list to the end, since `get_chats` only returns already loaded chats.
async fn list_chat_ids(
    client_id: TdlibClientId,
    list: enums::ChatList,
) -> Result<Vec<i64>, AdapterError> {
    loop {
        match functions::load_chats(Some(list.clone()), CHAT_LOAD_PAGE, client_id.raw()).await {
            Ok(()) => {}
            // TDLib answers 404 once the whole list is loaded.
            Err(error) if error.code == 404 => break,
            Err(error) => return Err(map_tdlib_error(error)),
        }
    }

    let chats = functions::get_chats(Some(list), MAX_CHATS, client_id.raw())
        .await
        .map_err(map_tdlib_error)?;

    let enums::Chats::Chats(chats) = chats;
    Ok(chats.chat_ids)
}

/// Every chat in the main list and the archive.
pub async fn list_chat_scopes(
    client_id: TdlibClientId,
) -> Result<Vec<TelegramChatScope>, AdapterError> {
    let mut chat_ids = list_chat_ids(client_id, enums::ChatList::Main).await?;
    for chat_id in list_chat_ids(client_id, enums::ChatList::Archive).await? {
        if !chat_ids.contains(&chat_id) {
            chat_ids.push(chat_id);
        }
    }
    let mut scopes = Vec::with_capacity(chat_ids.len());

    for chat_id in chat_ids {
        let chat = functions::get_chat(chat_id, client_id.raw())
            .await
            .map_err(map_tdlib_error)?;
        let enums::Chat::Chat(chat) = chat;
        scopes.push(map_chat_scope(&chat));
    }

    Ok(scopes)
}

/// Searches by sender, so a page holds only the user's messages regardless of how
/// deep they sit in the history. Not supported by TDLib for secret chats.
pub async fn search_own_messages(
    client_id: TdlibClientId,
    chat_id: i64,
    current_user_id: i64,
    from_message_id: i64,
    limit: i32,
) -> Result<OwnMessagePage, AdapterError> {
    let sender = enums::MessageSender::User(types::MessageSenderUser {
        user_id: current_user_id,
    });
    let found = functions::search_chat_messages(
        chat_id,
        None,
        String::new(),
        Some(sender),
        from_message_id,
        0,
        limit,
        None,
        client_id.raw(),
    )
    .await
    .map_err(map_tdlib_error)?;

    let enums::FoundChatMessages::FoundChatMessages(found) = found;
    Ok(OwnMessagePage {
        next_from_message_id: found.next_from_message_id,
        total_count: found.total_count,
        messages: found
            .messages
            .into_iter()
            .filter(|message| is_from_user(message, current_user_id))
            .map(|message| TelegramMessageRef {
                chat_id: message.chat_id,
                message_id: message.id,
                sent_at_epoch_secs: message.date,
                kind: classify_message_content(&message.content),
                text: extract_message_text(&message.content),
                media: message_files(&message.content)
                    .into_iter()
                    .map(Attachment::into_media_ref)
                    .collect(),
            })
            .collect(),
    })
}

/// Downloads one of a message's files to TDLib's files directory. Re-reads the
/// message so the file id and its server reference are current.
pub async fn download_message_file(
    client_id: TdlibClientId,
    chat_id: i64,
    message_id: i64,
    unique_id: &str,
) -> Result<FetchedMedia, AdapterError> {
    let enums::Message::Message(message) =
        functions::get_message(chat_id, message_id, client_id.raw())
            .await
            .map_err(map_tdlib_error)?;
    let file = message_files(&message.content)
        .into_iter()
        .map(|attachment| attachment.file)
        .find(|file| file.remote.unique_id == unique_id)
        .ok_or_else(|| AdapterError::Platform("the message no longer has this file".into()))?;

    let enums::File::File(downloaded) =
        functions::download_file(file.id, DOWNLOAD_PRIORITY, 0, 0, true, client_id.raw())
            .await
            .map_err(map_download_error)?;
    let bytes_on_disk = std::fs::metadata(&downloaded.local.path).map_or(0, |meta| meta.len());
    if !download_is_complete(&downloaded, bytes_on_disk) {
        return Err(AdapterError::Platform(
            "the file could not be downloaded".into(),
        ));
    }
    Ok(FetchedMedia {
        path: downloaded.local.path.into(),
        handle: i64::from(downloaded.id),
    })
}

/// Removes a downloaded file from TDLib's files directory, which is not encrypted.
pub async fn delete_downloaded_file(
    client_id: TdlibClientId,
    file_id: i32,
) -> Result<(), AdapterError> {
    functions::delete_file(file_id, client_id.raw())
        .await
        .map_err(map_tdlib_error)
}

pub async fn delete_message_batch(
    client_id: TdlibClientId,
    chat_id: i64,
    message_ids: Vec<i64>,
    revoke: bool,
) -> Result<(), AdapterError> {
    if message_ids.is_empty() {
        return Ok(());
    }

    functions::delete_messages(chat_id, message_ids, revoke, client_id.raw())
        .await
        .map_err(map_tdlib_error)
}

fn map_chat_scope(chat: &types::Chat) -> TelegramChatScope {
    TelegramChatScope {
        id: chat.id,
        title: chat.title.clone(),
        kind: classify_chat_type(&chat.r#type),
        can_delete_for_all_users: chat.can_be_deleted_for_all_users,
        can_delete_only_for_self: chat.can_be_deleted_only_for_self,
        cleanability: TelegramCleanability::from_flags(
            chat.can_be_deleted_for_all_users,
            chat.can_be_deleted_only_for_self,
        ),
    }
}

fn classify_chat_type(chat_type: &enums::ChatType) -> TelegramChatKind {
    match chat_type {
        enums::ChatType::Private(_) => TelegramChatKind::Private,
        enums::ChatType::BasicGroup(_) => TelegramChatKind::Group,
        enums::ChatType::Supergroup(supergroup) if supergroup.is_channel => {
            TelegramChatKind::Channel
        }
        enums::ChatType::Supergroup(_) => TelegramChatKind::Group,
        enums::ChatType::Secret(_) => TelegramChatKind::Secret,
    }
}

fn is_from_user(message: &types::Message, current_user_id: i64) -> bool {
    matches!(
        &message.sender_id,
        enums::MessageSender::User(sender) if sender.user_id == current_user_id
    )
}

fn classify_message_content(content: &enums::MessageContent) -> TelegramMessageKind {
    match content {
        enums::MessageContent::MessageText(_) => TelegramMessageKind::Text,
        enums::MessageContent::MessageAnimation(_)
        | enums::MessageContent::MessageAudio(_)
        | enums::MessageContent::MessageDocument(_)
        | enums::MessageContent::MessagePaidMedia(_)
        | enums::MessageContent::MessagePhoto(_)
        | enums::MessageContent::MessageSticker(_)
        | enums::MessageContent::MessageVideo(_)
        | enums::MessageContent::MessageVideoNote(_)
        | enums::MessageContent::MessageVoiceNote(_)
        | enums::MessageContent::MessageExpiredPhoto
        | enums::MessageContent::MessageExpiredVideo
        | enums::MessageContent::MessageExpiredVideoNote
        | enums::MessageContent::MessageExpiredVoiceNote => TelegramMessageKind::Media,
        _ => TelegramMessageKind::Other,
    }
}

fn extract_message_text(content: &enums::MessageContent) -> Option<String> {
    let text = match content {
        enums::MessageContent::MessageText(text) => &text.text,
        enums::MessageContent::MessageAnimation(media) => &media.caption,
        enums::MessageContent::MessageAudio(media) => &media.caption,
        enums::MessageContent::MessageDocument(media) => &media.caption,
        enums::MessageContent::MessagePaidMedia(media) => &media.caption,
        enums::MessageContent::MessagePhoto(media) => &media.caption,
        enums::MessageContent::MessageVideo(media) => &media.caption,
        enums::MessageContent::MessageVoiceNote(media) => &media.caption,
        _ => return None,
    };
    (!text.text.is_empty()).then(|| text.text.clone())
}

struct Attachment<'a> {
    file: &'a types::File,
    file_name: Option<String>,
    mime: Option<String>,
}

impl<'a> Attachment<'a> {
    fn new(file: &'a types::File, file_name: &str, mime: &str) -> Self {
        let present = |value: &str| (!value.is_empty()).then(|| value.to_owned());
        Self {
            file,
            file_name: present(file_name),
            mime: present(mime),
        }
    }

    /// Stores `unique_id` as the locator: it is stable across sessions, unlike
    /// TDLib's numeric file id.
    fn into_media_ref(self) -> MediaRef {
        MediaRef {
            url: self.file.remote.unique_id.clone(),
            mime: self.mime,
            file_name: self.file_name,
            size: Some(known_size(self.file)),
        }
    }
}

/// The files worth keeping from a message. Expired media and previews of paid
/// media have none, so such a message backs up as its metadata alone.
fn message_files(content: &enums::MessageContent) -> Vec<Attachment<'_>> {
    match content {
        enums::MessageContent::MessageAnimation(media) => {
            let animation = &media.animation;
            vec![Attachment::new(
                &animation.animation,
                &animation.file_name,
                &animation.mime_type,
            )]
        }
        enums::MessageContent::MessageAudio(media) => {
            let audio = &media.audio;
            vec![Attachment::new(
                &audio.audio,
                &audio.file_name,
                &audio.mime_type,
            )]
        }
        enums::MessageContent::MessageDocument(media) => {
            let document = &media.document;
            vec![Attachment::new(
                &document.document,
                &document.file_name,
                &document.mime_type,
            )]
        }
        enums::MessageContent::MessagePaidMedia(media) => {
            media.media.iter().filter_map(paid_media_file).collect()
        }
        enums::MessageContent::MessagePhoto(media) => {
            largest_photo(&media.photo).into_iter().collect()
        }
        enums::MessageContent::MessageSticker(media) => {
            vec![Attachment::new(&media.sticker.sticker, "", "")]
        }
        enums::MessageContent::MessageVideo(media) => vec![video_file(&media.video)],
        enums::MessageContent::MessageVideoNote(media) => {
            vec![Attachment::new(&media.video_note.video, "", "video/mp4")]
        }
        enums::MessageContent::MessageVoiceNote(media) => {
            let voice = &media.voice_note;
            vec![Attachment::new(&voice.voice, "", &voice.mime_type)]
        }
        _ => Vec::new(),
    }
}

fn paid_media_file(media: &enums::PaidMedia) -> Option<Attachment<'_>> {
    match media {
        enums::PaidMedia::Photo(paid) => largest_photo(&paid.photo),
        enums::PaidMedia::Video(paid) => Some(video_file(&paid.video)),
        _ => None,
    }
}

fn video_file(video: &types::Video) -> Attachment<'_> {
    Attachment::new(&video.video, &video.file_name, &video.mime_type)
}

fn largest_photo(photo: &types::Photo) -> Option<Attachment<'_>> {
    photo
        .sizes
        .iter()
        .max_by_key(|size| i64::from(size.width) * i64::from(size.height))
        .map(|size| Attachment::new(&size.photo, "", "image/jpeg"))
}

/// The message goes once its file is archived, so the bytes on disk have to agree
/// with TDLib's flag. A `size` of 0 means TDLib does not know the exact size.
fn download_is_complete(file: &types::File, bytes_on_disk: u64) -> bool {
    file.local.is_downloading_completed
        && bytes_on_disk > 0
        && (file.size == 0 || bytes_on_disk == file.size as u64)
}

/// A file's `size` is 0 until TDLib learns it; `expected_size` is the estimate.
fn known_size(file: &types::File) -> u64 {
    file.size.max(file.expected_size).max(0) as u64
}

fn map_tdlib_error(error: types::Error) -> AdapterError {
    if let Some(retry_after_secs) = parse_flood_wait(&error.message) {
        return AdapterError::RateLimited { retry_after_secs };
    }

    match error.code {
        401 => AdapterError::Auth(error.message),
        404 => AdapterError::NotFound,
        429 => AdapterError::RateLimited {
            retry_after_secs: 60,
        },
        _ => AdapterError::Platform(format!("TDLib {}: {}", error.code, error.message)),
    }
}

/// A 404 here means the file is gone, not the message, so it must not read as
/// "already deleted".
fn map_download_error(error: types::Error) -> AdapterError {
    match map_tdlib_error(error) {
        AdapterError::NotFound => AdapterError::Platform("the file is no longer available".into()),
        other => other,
    }
}

fn parse_flood_wait(message: &str) -> Option<u64> {
    message
        .strip_prefix("FLOOD_WAIT_")
        .and_then(|secs| secs.parse::<u64>().ok())
}

#[cfg(all(test, any(feature = "tdlib-local", feature = "tdlib-download")))]
mod tests {
    use super::*;

    #[test]
    fn classifies_supergroup_channel_flag() {
        let group = enums::ChatType::Supergroup(types::ChatTypeSupergroup {
            supergroup_id: 1,
            is_channel: false,
        });
        let channel = enums::ChatType::Supergroup(types::ChatTypeSupergroup {
            supergroup_id: 2,
            is_channel: true,
        });

        assert_eq!(classify_chat_type(&group), TelegramChatKind::Group);
        assert_eq!(classify_chat_type(&channel), TelegramChatKind::Channel);
    }

    #[test]
    fn cleanability_prefers_delete_for_everyone() {
        assert_eq!(
            TelegramCleanability::from_flags(true, true),
            TelegramCleanability::DeleteForEveryone
        );
        assert_eq!(
            TelegramCleanability::from_flags(false, true),
            TelegramCleanability::OnlyForSelf
        );
        assert_eq!(
            TelegramCleanability::from_flags(false, false),
            TelegramCleanability::NotCleanable
        );
    }

    fn file(unique_id: &str, size: i64, expected_size: i64) -> types::File {
        types::File {
            id: 1,
            size,
            expected_size,
            local: types::LocalFile {
                path: String::new(),
                can_be_downloaded: true,
                can_be_deleted: false,
                is_downloading_active: false,
                is_downloading_completed: false,
                download_offset: 0,
                downloaded_prefix_size: 0,
                downloaded_size: 0,
            },
            remote: types::RemoteFile {
                id: format!("remote-{unique_id}"),
                unique_id: unique_id.into(),
                is_uploading_active: false,
                is_uploading_completed: true,
                uploaded_size: 0,
            },
        }
    }

    fn caption(text: &str) -> types::FormattedText {
        types::FormattedText {
            text: text.into(),
            entities: Vec::new(),
        }
    }

    fn document_message(text: &str) -> enums::MessageContent {
        enums::MessageContent::MessageDocument(types::MessageDocument {
            document: types::Document {
                file_name: "report.pdf".into(),
                mime_type: "application/pdf".into(),
                minithumbnail: None,
                thumbnail: None,
                document: file("doc", 2048, 0),
            },
            caption: caption(text),
        })
    }

    fn photo_message(sizes: &[(i32, &str)]) -> enums::MessageContent {
        enums::MessageContent::MessagePhoto(types::MessagePhoto {
            photo: types::Photo {
                has_stickers: false,
                minithumbnail: None,
                sizes: sizes
                    .iter()
                    .map(|(side, id)| types::PhotoSize {
                        r#type: "x".into(),
                        photo: file(id, 10, 0),
                        width: *side,
                        height: *side,
                        progressive_sizes: Vec::new(),
                    })
                    .collect(),
            },
            caption: caption(""),
            show_caption_above_media: false,
            has_spoiler: false,
            is_secret: false,
        })
    }

    #[test]
    fn caption_is_kept_as_the_message_text() {
        assert_eq!(
            extract_message_text(&document_message("quarterly numbers")),
            Some("quarterly numbers".into())
        );
    }

    #[test]
    fn media_without_a_caption_has_no_text() {
        assert_eq!(extract_message_text(&document_message("")), None);
    }

    #[test]
    fn document_keeps_its_name_type_and_size() {
        let content = document_message("");
        let files = message_files(&content);

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].file.remote.unique_id, "doc");
        assert_eq!(files[0].file_name.as_deref(), Some("report.pdf"));
        assert_eq!(files[0].mime.as_deref(), Some("application/pdf"));
        assert_eq!(known_size(files[0].file), 2048);
    }

    #[test]
    fn photo_backs_up_only_its_largest_size() {
        let content = photo_message(&[(90, "small"), (1280, "large"), (320, "medium")]);
        let files = message_files(&content);

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].file.remote.unique_id, "large");
    }

    #[test]
    fn expired_media_has_no_file_to_fetch() {
        assert!(message_files(&enums::MessageContent::MessageExpiredPhoto).is_empty());
    }

    #[test]
    fn paid_media_without_a_file_has_nothing_to_fetch() {
        let content = enums::MessageContent::MessagePaidMedia(types::MessagePaidMedia {
            star_count: 1,
            media: vec![enums::PaidMedia::Unsupported],
            caption: caption("paid"),
            show_caption_above_media: false,
        });

        assert!(message_files(&content).is_empty());
        assert_eq!(extract_message_text(&content), Some("paid".into()));
    }

    #[test]
    fn a_download_counts_only_when_the_bytes_on_disk_agree() {
        let mut finished = file("a", 100, 0);
        finished.local.is_downloading_completed = true;

        assert!(download_is_complete(&finished, 100));
        assert!(!download_is_complete(&finished, 99), "short file");
        assert!(!download_is_complete(&finished, 0), "empty file");
        assert!(
            !download_is_complete(&file("b", 100, 0), 100),
            "still downloading"
        );

        let mut unknown_size = file("c", 0, 500);
        unknown_size.local.is_downloading_completed = true;
        assert!(download_is_complete(&unknown_size, 480));
    }

    #[test]
    fn size_falls_back_to_the_estimate_while_unknown() {
        assert_eq!(known_size(&file("a", 0, 500)), 500);
        assert_eq!(known_size(&file("b", 700, 0)), 700);
    }

    #[test]
    fn a_missing_file_does_not_read_as_a_deleted_message() {
        let error = map_download_error(types::Error {
            code: 404,
            message: "Not Found".into(),
        });

        assert!(matches!(error, AdapterError::Platform(_)));
    }

    #[test]
    fn maps_flood_wait_errors_to_rate_limit() {
        let error = map_tdlib_error(types::Error {
            code: 420,
            message: "FLOOD_WAIT_17".into(),
        });

        assert!(matches!(
            error,
            AdapterError::RateLimited {
                retry_after_secs: 17
            }
        ));
    }
}

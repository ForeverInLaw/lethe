//! Narrow TDLib boundary for Telegram chat-scope discovery and deletion calls.
//!
//! This module is feature-gated so the default workspace build does not require
//! native TDLib. Use `tdlib-docs` with `cargo check` to type-check generated
//! TDLib bindings; test binaries still need native tdjson symbols.

use std::future::Future;
use std::pin::pin;

use futures::future::{self, Either};
use lethe_adapter::{AdapterError, DeleteReach, FetchedMedia, MediaRef, PlatformRecord};
use tdlib_rs::{enums, functions, types};

use crate::DeleteRights;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelegramChatScope {
    pub id: i64,
    pub title: String,
    pub kind: TelegramChatKind,
    /// Changes whenever the chat gets a new message, so a count taken while it was
    /// the same still holds. None when TDLib does not know the last message.
    pub last_message_id: Option<i64>,
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
    /// What the message is, for anything but plain text: `photo`, `poll`, `chat_join`.
    pub subtype: Option<&'static str>,
    /// Message text or media caption, kept in the backup with the message. A poll,
    /// contact or venue has its question, name or title here.
    pub text: Option<String>,
    pub media: Vec<MediaRef>,
    /// The whole message, which is all the backup has of a poll, contact or location.
    pub platform_record: PlatformRecord,
    /// What TDLib does not hand over, so the backup cannot hold it.
    pub backup_gap: Option<String>,
    /// How far deleting this message goes, as Telegram says for this account.
    pub delete_reach: DeleteReach,
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
    let mut messages = Vec::with_capacity(found.messages.len());
    for message in found.messages.iter().filter(|message| is_from_user(message, current_user_id)) {
        match read_delete_rights(client_id, chat_id, message.id).await {
            Ok(rights) => messages.push(message_ref(message, rights.reach(chat_id, current_user_id))?),
            // Deleted since the search found it, so there is nothing left to clean.
            Err(AdapterError::NotFound) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(OwnMessagePage {
        next_from_message_id: found.next_from_message_id,
        total_count: found.total_count,
        messages,
    })
}

/// What Telegram lets this account do with a message right now. An offline call that
/// only knows loaded messages, so one that is not loaded, as after a restart, is
/// fetched first. `NotFound` means the message is gone.
pub async fn read_delete_rights(
    client_id: TdlibClientId,
    chat_id: i64,
    message_id: i64,
) -> Result<DeleteRights, AdapterError> {
    let properties = match functions::get_message_properties(chat_id, message_id, client_id.raw()).await {
        Err(error) if is_message_not_loaded(&error) => {
            functions::get_message(chat_id, message_id, client_id.raw())
                .await
                .map_err(map_tdlib_error)?;
            functions::get_message_properties(chat_id, message_id, client_id.raw()).await
        }
        other => other,
    };
    let enums::MessageProperties::MessageProperties(properties) = properties.map_err(map_tdlib_error)?;
    Ok(DeleteRights {
        for_everyone: properties.can_be_deleted_for_all_users,
        for_self: properties.can_be_deleted_only_for_self,
    })
}

fn is_message_not_loaded(error: &types::Error) -> bool {
    error.code == 404 || error.message == "Message not found"
}

fn message_ref(message: &types::Message, delete_reach: DeleteReach) -> Result<TelegramMessageRef, AdapterError> {
    Ok(TelegramMessageRef {
        chat_id: message.chat_id,
        message_id: message.id,
        sent_at_epoch_secs: message.date,
        kind: classify_message_content(&message.content),
        subtype: message_subtype(message),
        text: extract_message_text(&message.content),
        media: message_files(&message.content)
            .into_iter()
            .map(Attachment::into_media_ref)
            .collect(),
        platform_record: PlatformRecord::capture(message)?,
        backup_gap: backup_gap(&message.content).map(str::to_owned),
        delete_reach,
    })
}

/// Downloads one of a message's files to TDLib's files directory. Re-reads the
/// message so the file id and its server reference are current. TDLib waits out a
/// lost connection without returning, so the download is called off once
/// `connection_lost` completes and fails as a network error.
pub async fn download_message_file(
    client_id: TdlibClientId,
    chat_id: i64,
    message_id: i64,
    unique_id: &str,
    connection_lost: impl Future<Output = ()>,
) -> Result<FetchedMedia, AdapterError> {
    let enums::Message::Message(message) =
        functions::get_message(chat_id, message_id, client_id.raw())
            .await
            .map_err(map_message_read_error)?;
    let file = message_files(&message.content)
        .into_iter()
        .map(|attachment| attachment.file)
        .find(|file| file.remote.unique_id == unique_id)
        .ok_or_else(|| AdapterError::FileRefused("the message no longer has this file".into()))?;

    let download = functions::download_file(file.id, DOWNLOAD_PRIORITY, 0, 0, true, client_id.raw());
    let downloaded = match future::select(pin!(download), pin!(connection_lost)).await {
        Either::Left((downloaded, _)) => downloaded.map_err(map_download_error),
        Either::Right(((), _)) => {
            let cancelled = functions::cancel_download_file(file.id, false, client_id.raw()).await;
            let lost = "the connection to Telegram was lost";
            Err(AdapterError::Transport(match cancelled {
                Ok(_) => lost.into(),
                Err(error) => format!("{lost}, and the download kept going: {}", error.message),
            }))
        }
    };
    let fetched = downloaded
        .and_then(|enums::File::File(downloaded)| {
            let bytes_on_disk =
                std::fs::metadata(&downloaded.local.path).map_or(0, |meta| meta.len());
            if !download_is_complete(&downloaded, bytes_on_disk) {
                return Err(AdapterError::Transport(
                    "the file could not be downloaded".into(),
                ));
            }
            Ok(FetchedMedia {
                path: downloaded.local.path.into(),
                handle: i64::from(downloaded.id),
            })
        });

    // Core only releases what it receives, so a partial download is removed here.
    if fetched.is_err() {
        if let Err(error) = delete_downloaded_file(client_id, file.id).await {
            return Err(AdapterError::Transport(format!(
                "the file could not be downloaded, and its partial copy stayed on disk: {error}"
            )));
        }
    }
    fetched
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
        last_message_id: chat.last_message.as_ref().map(|message| message.id),
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

/// A stable key for what the message is, which the app words the way Telegram
/// does. Plain text needs none. Kinds a user rarely sends share `service`.
fn message_subtype(message: &types::Message) -> Option<&'static str> {
    use enums::MessageContent::*;
    Some(match &message.content {
        MessageText(_) | MessageAnimatedEmoji(_) => return None,
        MessageAnimation(_) => "animation",
        MessageAudio(_) => "audio",
        MessageDocument(_) => "document",
        MessagePaidMedia(_) => "paid_media",
        MessagePhoto(_) => "photo",
        MessageSticker(_) => "sticker",
        MessageVideo(_) => "video",
        MessageVideoNote(_) => "video_note",
        MessageVoiceNote(_) => "voice_note",
        MessageExpiredPhoto | MessageExpiredVideo | MessageExpiredVideoNote
        | MessageExpiredVoiceNote => "expired_media",
        MessageLocation(_) => "location",
        MessageVenue(_) => "venue",
        MessageContact(_) => "contact",
        MessageDice(_) | MessageStakeDice(_) => "dice",
        MessageGame(_) => "game",
        MessagePoll(_) => "poll",
        MessageStory(_) => "story",
        MessageChecklist(_) => "checklist",
        MessageChecklistTasksDone(_) | MessageChecklistTasksAdded(_) => "checklist_changed",
        MessageInvoice(_) => "invoice",
        MessageCall(_) => "call",
        MessageGroupCall(_) | MessageVideoChatScheduled(_) | MessageVideoChatStarted(_)
        | MessageVideoChatEnded(_) | MessageInviteVideoChatParticipants(_) => "video_chat",
        MessageBasicGroupChatCreate(_) | MessageSupergroupChatCreate(_) => "chat_create",
        MessageChatChangeTitle(_) => "chat_change_title",
        MessageChatChangePhoto(_) => "chat_change_photo",
        MessageChatDeletePhoto => "chat_delete_photo",
        MessageChatAddMembers(_) => "chat_add_members",
        MessageChatJoinByLink | MessageChatJoinByRequest => "chat_join",
        MessageChatDeleteMember(member) if is_from_user(message, member.user_id) => "chat_leave",
        MessageChatDeleteMember(_) => "chat_remove_member",
        MessageChatUpgradeTo(_) | MessageChatUpgradeFrom(_) => "chat_upgrade",
        MessagePinMessage(_) => "pin_message",
        MessageScreenshotTaken => "screenshot_taken",
        MessageChatSetBackground(_) | MessageChatSetTheme(_) => "chat_set_theme",
        MessageChatSetMessageAutoDeleteTime(_) => "auto_delete_timer",
        MessageForumTopicCreated(_) => "topic_create",
        MessageForumTopicEdited(_) | MessageForumTopicIsClosedToggled(_)
        | MessageForumTopicIsHiddenToggled(_) => "topic_change",
        MessageGameScore(_) => "game_score",
        MessageContactRegistered => "joined_telegram",
        MessageGiftedPremium(_) | MessagePremiumGiftCode(_) | MessageGiftedStars(_)
        | MessageGiftedTon(_) | MessageGiveawayPrizeStars(_) | MessageGift(_)
        | MessageUpgradedGift(_) | MessageRefundedUpgradedGift(_) => "gift",
        MessageGiveawayCreated(_) | MessageGiveaway(_) | MessageGiveawayCompleted(_)
        | MessageGiveawayWinners(_) => "giveaway",
        MessagePaymentSuccessful(_) | MessagePaymentSuccessfulBot(_)
        | MessagePaymentRefunded(_) => "payment",
        MessageUnsupported => "unsupported",
        _ => "service",
    })
}

/// The words the user put in a message: its text, caption, or what it names, such
/// as a poll's question or a new chat title. The keyword filter reads them too.
fn extract_message_text(content: &enums::MessageContent) -> Option<String> {
    use enums::MessageContent::*;
    let text = match content {
        MessageText(text) => &text.text.text,
        MessageAnimation(media) => &media.caption.text,
        MessageAudio(media) => &media.caption.text,
        MessageDocument(media) => &media.caption.text,
        MessagePaidMedia(media) => &media.caption.text,
        MessagePhoto(media) => &media.caption.text,
        MessageVideo(media) => &media.caption.text,
        MessageVoiceNote(media) => &media.caption.text,
        MessageAnimatedEmoji(emoji) => &emoji.emoji,
        MessageDice(dice) => &dice.emoji,
        MessagePoll(poll) => &poll.poll.question.text,
        MessageChecklist(checklist) => &checklist.list.title.text,
        MessageVenue(venue) => &venue.venue.title,
        MessageContact(contact) => {
            let name = format!("{} {}", contact.contact.first_name, contact.contact.last_name);
            let name = name.trim();
            return (!name.is_empty()).then(|| name.to_owned());
        }
        MessageChatChangeTitle(change) => &change.title,
        MessageForumTopicCreated(topic) => &topic.name,
        _ => return None,
    };
    (!text.is_empty()).then(|| text.clone())
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
            size: known_size(self.file),
        }
    }
}

/// What the message holds that TDLib does not hand over. Expired media is not on
/// the list: Telegram no longer has it, so a delete takes nothing away.
fn backup_gap(content: &enums::MessageContent) -> Option<&'static str> {
    match content {
        enums::MessageContent::MessageUnsupported => {
            Some("this version of TDLib cannot read this kind of message")
        }
        enums::MessageContent::MessagePhoto(media) if largest_photo(&media.photo).is_none() => {
            Some("Telegram does not hand over this photo")
        }
        enums::MessageContent::MessagePaidMedia(media)
            if media.media.iter().any(|paid| paid_media_file(paid).is_none()) =>
        {
            Some("Telegram does not hand over this paid media")
        }
        _ => None,
    }
}

/// The files worth keeping from a message.
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
/// With neither, the size is unknown: Telegram holds no empty files.
fn known_size(file: &types::File) -> Option<u64> {
    let size = file.size.max(file.expected_size);
    (size > 0).then_some(size as u64)
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

/// A server fault says nothing about the message, so it is worth another try.
fn map_message_read_error(error: types::Error) -> AdapterError {
    let code = error.code;
    match map_tdlib_error(error) {
        AdapterError::Platform(message) if code >= 500 => AdapterError::Transport(message),
        other => other,
    }
}

/// A 404 here means the file is gone, not the message, so it must not read as
/// "already deleted". Only a client error is Telegram refusing the file.
fn map_download_error(error: types::Error) -> AdapterError {
    let code = error.code;
    match map_tdlib_error(error) {
        AdapterError::NotFound => AdapterError::FileRefused("the file is no longer available".into()),
        AdapterError::Platform(message) if (400..500).contains(&code) => AdapterError::FileRefused(message),
        AdapterError::Platform(message) => AdapterError::Transport(message),
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

    fn tdlib_error(code: i32, message: &str) -> types::Error {
        types::Error { code, message: message.into() }
    }

    #[test]
    fn only_a_client_error_counts_as_telegram_refusing_a_file() {
        for code in [400, 404] {
            let error = map_download_error(tdlib_error(code, "no such file"));
            assert!(matches!(error, AdapterError::FileRefused(_)), "{code}: {error}");
        }
        assert!(matches!(map_download_error(tdlib_error(500, "internal")), AdapterError::Transport(_)));
        assert!(matches!(map_download_error(tdlib_error(401, "unauthorized")), AdapterError::Auth(_)));
        assert!(matches!(
            map_download_error(tdlib_error(420, "FLOOD_WAIT_5")),
            AdapterError::RateLimited { .. }
        ));
    }

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

    fn message_with(content: enums::MessageContent) -> types::Message {
        types::Message {
            id: 9,
            sender_id: enums::MessageSender::User(types::MessageSenderUser { user_id: 1 }),
            chat_id: 7,
            sending_state: None,
            scheduling_state: None,
            is_outgoing: true,
            is_pinned: false,
            is_from_offline: false,
            can_be_saved: true,
            has_timestamped_media: false,
            is_channel_post: false,
            is_paid_star_suggested_post: false,
            is_paid_ton_suggested_post: false,
            contains_unread_mention: false,
            date: 100,
            edit_date: 0,
            forward_info: None,
            import_info: None,
            interaction_info: None,
            unread_reactions: Vec::new(),
            fact_check: None,
            suggested_post_info: None,
            reply_to: None,
            topic_id: None,
            self_destruct_type: None,
            self_destruct_in: 0.0,
            auto_delete_in: 0.0,
            via_bot_user_id: 0,
            sender_business_bot_user_id: 0,
            sender_boost_count: 0,
            paid_message_star_count: 0,
            author_signature: String::new(),
            media_album_id: 0,
            effect_id: 0,
            restriction_info: None,
            summary_language_code: String::new(),
            content,
            reply_markup: None,
        }
    }

    fn record_of(content: enums::MessageContent) -> serde_json::Value {
        let message = message_ref(&message_with(content), DeleteReach::Everyone).unwrap();
        serde_json::from_str(message.platform_record.as_json()).unwrap()
    }

    fn gap_of(content: enums::MessageContent) -> Option<String> {
        message_ref(&message_with(content), DeleteReach::Everyone).unwrap().backup_gap
    }

    #[test]
    fn a_contact_is_kept_in_the_platform_record() {
        let record = record_of(enums::MessageContent::MessageContact(types::MessageContact {
            contact: types::Contact {
                phone_number: "+15550100".into(),
                first_name: "Sam".into(),
                last_name: String::new(),
                vcard: String::new(),
                user_id: 0,
            },
        }));
        assert_eq!(record["content"]["contact"]["phone_number"], "+15550100");
        assert_eq!(record["content"]["contact"]["first_name"], "Sam");
    }

    #[test]
    fn a_location_is_kept_in_the_platform_record() {
        let record = record_of(enums::MessageContent::MessageLocation(types::MessageLocation {
            location: types::Location {
                latitude: 52.5,
                longitude: 13.4,
                horizontal_accuracy: 0.0,
            },
            live_period: 0,
            expires_in: 0,
            heading: 0,
            proximity_alert_radius: 0,
        }));
        assert_eq!(record["content"]["location"]["latitude"], 52.5);
    }

    #[test]
    fn a_poll_is_kept_in_the_platform_record_and_has_nothing_missing() {
        let content = enums::MessageContent::MessagePoll(types::MessagePoll {
            poll: types::Poll {
                id: 1,
                question: caption("tea or coffee"),
                options: vec![types::PollOption {
                    text: caption("tea"),
                    voter_count: 2,
                    vote_percentage: 100,
                    is_chosen: false,
                    is_being_chosen: false,
                }],
                total_voter_count: 2,
                recent_voter_ids: Vec::new(),
                is_anonymous: true,
                r#type: enums::PollType::Regular(types::PollTypeRegular {
                    allow_multiple_answers: false,
                }),
                open_period: 0,
                close_date: 0,
                is_closed: false,
            },
        });

        assert_eq!(gap_of(content.clone()), None);
        let record = record_of(content);
        assert_eq!(record["content"]["poll"]["question"]["text"], "tea or coffee");
        assert_eq!(record["content"]["poll"]["options"][0]["text"]["text"], "tea");
    }

    fn described(message: types::Message) -> (Option<&'static str>, Option<String>) {
        let message = message_ref(&message, DeleteReach::Everyone).unwrap();
        (message.subtype, message.text)
    }

    fn poll(question: &str) -> enums::MessageContent {
        enums::MessageContent::MessagePoll(types::MessagePoll {
            poll: types::Poll {
                id: 1,
                question: caption(question),
                options: Vec::new(),
                total_voter_count: 0,
                recent_voter_ids: Vec::new(),
                is_anonymous: true,
                r#type: enums::PollType::Regular(types::PollTypeRegular {
                    allow_multiple_answers: false,
                }),
                open_period: 0,
                close_date: 0,
                is_closed: false,
            },
        })
    }

    #[test]
    fn a_poll_says_it_is_a_poll_and_keeps_its_question_as_text() {
        assert_eq!(
            described(message_with(poll("tea or coffee"))),
            (Some("poll"), Some("tea or coffee".into()))
        );
    }

    #[test]
    fn a_service_message_says_what_happened_and_has_no_text() {
        let joined = enums::MessageContent::MessageChatJoinByLink;
        let pinned = enums::MessageContent::MessagePinMessage(types::MessagePinMessage { message_id: 3 });
        assert_eq!(described(message_with(joined)), (Some("chat_join"), None));
        assert_eq!(described(message_with(pinned)), (Some("pin_message"), None));
    }

    #[test]
    fn removing_yourself_from_a_chat_reads_as_leaving_it() {
        let removed = |user_id| {
            enums::MessageContent::MessageChatDeleteMember(types::MessageChatDeleteMember { user_id })
        };
        // `message_with` sends as user 1.
        assert_eq!(described(message_with(removed(1))).0, Some("chat_leave"));
        assert_eq!(described(message_with(removed(2))).0, Some("chat_remove_member"));
    }

    #[test]
    fn a_photo_says_it_is_a_photo_and_keeps_its_caption() {
        let enums::MessageContent::MessagePhoto(mut photo) = photo_message(&[(90, "small")]) else {
            unreachable!()
        };
        photo.caption = caption("at the sea");
        assert_eq!(
            described(message_with(enums::MessageContent::MessagePhoto(photo))),
            (Some("photo"), Some("at the sea".into()))
        );
    }

    #[test]
    fn a_text_message_needs_no_description() {
        let text = enums::MessageContent::MessageText(types::MessageText {
            text: caption("hi"),
            link_preview: None,
            link_preview_options: None,
        });
        assert_eq!(described(message_with(text)), (None, Some("hi".into())));
    }

    #[test]
    fn a_message_tdlib_cannot_read_lacks_its_content() {
        assert!(gap_of(enums::MessageContent::MessageUnsupported).is_some());
    }

    #[test]
    fn a_photo_without_sizes_lacks_its_file() {
        assert!(gap_of(photo_message(&[])).is_some());
        assert_eq!(gap_of(photo_message(&[(90, "small")])), None);
    }

    #[test]
    fn paid_media_lacks_a_file_when_any_of_its_entries_has_none() {
        let paid = |media| {
            enums::MessageContent::MessagePaidMedia(types::MessagePaidMedia {
                star_count: 1,
                media,
                caption: caption("paid"),
                show_caption_above_media: false,
            })
        };
        let photo = || {
            let enums::MessageContent::MessagePhoto(message) = photo_message(&[(90, "small")]) else {
                unreachable!()
            };
            enums::PaidMedia::Photo(types::PaidMediaPhoto { photo: message.photo })
        };

        assert_eq!(gap_of(paid(vec![photo()])), None);
        assert!(gap_of(paid(vec![photo(), enums::PaidMedia::Unsupported])).is_some());
    }

    #[test]
    fn expired_media_has_nothing_left_to_lose() {
        assert_eq!(gap_of(enums::MessageContent::MessageExpiredPhoto), None);
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
        assert_eq!(known_size(files[0].file), Some(2048));
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
        assert_eq!(known_size(&file("a", 0, 500)), Some(500));
        assert_eq!(known_size(&file("b", 700, 0)), Some(700));
        assert_eq!(known_size(&file("c", 0, 0)), None);
    }

    #[test]
    fn a_missing_file_does_not_read_as_a_deleted_message() {
        let error = map_download_error(types::Error {
            code: 404,
            message: "Not Found".into(),
        });

        assert!(matches!(error, AdapterError::FileRefused(_)));
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

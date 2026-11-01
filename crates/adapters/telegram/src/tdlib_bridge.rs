//! Narrow TDLib boundary for Telegram chat-scope discovery and deletion calls.
//!
//! This module is feature-gated so the default workspace build does not require
//! native TDLib. Use `tdlib-docs` with `cargo check` to type-check generated
//! TDLib bindings; test binaries still need native tdjson symbols.

use lethe_adapter::AdapterError;
use tdlib_rs::{enums, functions, types};

const CHAT_LOAD_PAGE: i32 = 100;
const MAX_CHATS: i32 = 100_000;

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
    /// Plain message text, captured so the backup archives recoverable content
    /// rather than bare ids. ponytail: text only; media captions/bytes are the
    /// documented adapter follow-up.
    pub text: Option<String>,
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
            })
            .collect(),
    })
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
    match content {
        enums::MessageContent::MessageText(text) => Some(text.text.text.clone()),
        _ => None,
    }
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

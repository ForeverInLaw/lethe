//! Telegram adapter (M1 integration #3). Stub: descriptor + contract shell.
//! `api_id`/`api_hash` are injected at construction (BYO-first) — never embedded.

#[cfg(any(
    feature = "tdlib-docs",
    feature = "tdlib-local",
    feature = "tdlib-download"
))]
pub mod tdlib_bridge;

use std::collections::HashMap;

use async_trait::async_trait;
use lethe_adapter::{
    AdapterError, Capabilities, ContentType, Descriptor, EnumeratePlan, ItemRef, ItemStream,
    Outcome, PlatformAdapter, PushdownDim, RatePolicy, RiskClass,
};

const CONTENT_TYPES: &[ContentType] = &[ContentType::Dm, ContentType::Media];
const PUSHDOWN: &[PushdownDim] = &[PushdownDim::Scope, PushdownDim::DateRange];

/// Parse a Telegram `ItemRef` back into `(chat_id, message_id)`. Accepts both
/// the `token` form (`"{chat}:{message}"`) and the `platform_id` form
/// (`"telegram:{chat}:{message}"`). Returns `None` for anything malformed so
/// the caller can mark just that row failed instead of poisoning the batch.
pub fn parse_message_ref(item: &ItemRef) -> Option<(i64, i64)> {
    let raw = item
        .token
        .as_deref()
        .or_else(|| item.platform_id.strip_prefix("telegram:"))?;
    let (chat, message) = raw.split_once(':')?;
    Some((chat.parse().ok()?, message.parse().ok()?))
}

/// Reassemble per-message outcomes in the caller's input order from per-chat
/// batch-delete results. `parsed[i]` is the parse of input item `i` (`None` if
/// malformed); `chat_results[&chat]` is that chat's single delete result,
/// applied to every message that grouped under it. TDLib deletes per chat in
/// one call, so chat granularity is the finest signal we get.
pub fn assemble_outcomes(
    parsed: &[Option<(i64, i64)>],
    chat_results: &HashMap<i64, Result<(), AdapterError>>,
) -> Vec<Outcome> {
    parsed
        .iter()
        .map(|entry| match entry {
            None => Outcome::Failed {
                reason: "unparseable Telegram message ref".into(),
                retryable: false,
            },
            Some((chat_id, _)) => match chat_results.get(chat_id) {
                Some(result) => outcome_for(result),
                None => Outcome::Failed {
                    reason: format!("no delete result for chat {chat_id}"),
                    retryable: false,
                },
            },
        })
        .collect()
}

fn outcome_for(result: &Result<(), AdapterError>) -> Outcome {
    match result {
        Ok(()) => Outcome::Deleted,
        Err(AdapterError::RateLimited { retry_after_secs }) => Outcome::RateLimited {
            retry_after_secs: *retry_after_secs,
        },
        // NotFound == already gone: idempotent resume treats it as success.
        Err(AdapterError::NotFound) => Outcome::Skipped {
            reason: "already deleted".into(),
        },
        Err(AdapterError::Transport(e)) => Outcome::Failed {
            reason: e.clone(),
            retryable: true,
        },
        Err(e) => Outcome::Failed {
            reason: e.to_string(),
            retryable: false,
        },
    }
}

/// Injected app credentials (BYO). No defaults live in this crate.
pub struct ApiCredentials {
    pub api_id: i32,
    pub api_hash: String,
}

pub struct TelegramAdapter {
    descriptor: Descriptor,
    // TDLib client/session lives in the app layer until the auth vertical is wired.
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
            capabilities: Capabilities {
                can_redact: false,
                can_undo: false,
                batch_delete_max: 100,
            },
            // Placeholder until the TDLib egress sandbox is explicit.
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
        RatePolicy {
            max_per_sec: 20.0,
            max_per_min: Some(300),
            burst: 20,
        }
    }
}

#[cfg(test)]
mod delete_mapping_tests {
    use super::*;

    fn iref(platform_id: &str, token: Option<&str>) -> ItemRef {
        ItemRef {
            platform_id: platform_id.into(),
            token: token.map(Into::into),
        }
    }

    #[test]
    fn parses_token_and_platform_id_forms() {
        assert_eq!(
            parse_message_ref(&iref("telegram:123:456", Some("123:456"))),
            Some((123, 456))
        );
        // Negative supergroup id, token absent -> fall back to platform_id.
        assert_eq!(
            parse_message_ref(&iref("telegram:-1001234:9", None)),
            Some((-1001234, 9))
        );
        assert_eq!(parse_message_ref(&iref("nope", None)), None);
        assert_eq!(parse_message_ref(&iref("telegram:x:y", None)), None);
    }

    #[test]
    fn reassembles_in_input_order_grouped_by_chat() {
        // chat 1 msg10, chat 2 msg20, malformed, chat 1 msg11.
        let parsed = vec![Some((1, 10)), Some((2, 20)), None, Some((1, 11))];
        let mut results = HashMap::new();
        results.insert(1, Ok(()));
        results.insert(2, Err(AdapterError::RateLimited { retry_after_secs: 7 }));

        let out = assemble_outcomes(&parsed, &results);
        assert_eq!(out.len(), 4);
        assert!(matches!(out[0], Outcome::Deleted));
        assert!(matches!(out[1], Outcome::RateLimited { retry_after_secs: 7 }));
        assert!(matches!(out[2], Outcome::Failed { retryable: false, .. }));
        // Same chat as out[0] -> shares the chat's success result.
        assert!(matches!(out[3], Outcome::Deleted));
    }

    #[test]
    fn not_found_maps_to_skipped() {
        let parsed = vec![Some((5, 1))];
        let mut results = HashMap::new();
        results.insert(5, Err(AdapterError::NotFound));
        assert!(matches!(
            assemble_outcomes(&parsed, &results)[0],
            Outcome::Skipped { .. }
        ));
    }
}

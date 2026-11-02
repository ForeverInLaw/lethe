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
    AdapterError, Capabilities, ContentType, DeleteReach, Descriptor, EnumeratePlan, ItemRef, ItemStream,
    Outcome, PlatformAdapter, PushdownDim, RatePolicy, RiskClass,
};

const CONTENT_TYPES: &[ContentType] = &[ContentType::Dm, ContentType::Media];
const PUSHDOWN: &[PushdownDim] = &[PushdownDim::Scope, PushdownDim::DateRange];

/// Marks a token whose message was previewed as going only for this account.
const ONLY_FOR_SELF_SUFFIX: &str = ":self";

/// The routing token of a message, holding how far its delete went in the preview.
pub fn message_token(chat_id: i64, message_id: i64, reach: DeleteReach) -> String {
    let suffix = if reach == DeleteReach::OnlyForSelf { ONLY_FOR_SELF_SUFFIX } else { "" };
    format!("{chat_id}:{message_id}{suffix}")
}

/// Parse a Telegram `ItemRef` back into `(chat_id, message_id)`. Accepts both
/// the `token` form (`"{chat}:{message}"`) and the `platform_id` form
/// (`"telegram:{chat}:{message}"`). Returns `None` for anything malformed so
/// the caller can mark just that row failed instead of poisoning the batch.
pub fn parse_message_ref(item: &ItemRef) -> Option<(i64, i64)> {
    let raw = item
        .token
        .as_deref()
        .or_else(|| item.platform_id.strip_prefix("telegram:"))?;
    let raw = raw.strip_suffix(ONLY_FOR_SELF_SUFFIX).unwrap_or(raw);
    let (chat, message) = raw.split_once(':')?;
    Some((chat.parse().ok()?, message.parse().ok()?))
}

fn previewed_reach(item: &ItemRef) -> DeleteReach {
    match item.token.as_deref() {
        Some(token) if token.ends_with(ONLY_FOR_SELF_SUFFIX) => DeleteReach::OnlyForSelf,
        _ => DeleteReach::Everyone,
    }
}

/// What Telegram lets this account do with a message right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeleteRights {
    pub for_everyone: bool,
    pub for_self: bool,
}

impl DeleteRights {
    /// Saved Messages can only be deleted "for self", but nobody else ever sees them,
    /// so there that removes the message for everyone who could see it.
    pub fn reach(self, chat_id: i64, current_user_id: i64) -> DeleteReach {
        if self.for_everyone || (self.for_self && chat_id == current_user_id) {
            DeleteReach::Everyone
        } else if self.for_self {
            DeleteReach::OnlyForSelf
        } else {
            DeleteReach::Nowhere
        }
    }
}

/// One TDLib delete call, which carries a single `revoke` flag for all its messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeleteCall {
    pub chat_id: i64,
    pub revoke: bool,
}

/// How one batch reaches Telegram. TDLib refuses a whole call over one message it
/// cannot delete, and does not check `revoke` for a user account, so every message
/// is checked first and a message whose rights moved since the preview stays.
pub struct DeletePlan {
    pub calls: HashMap<DeleteCall, Vec<i64>>,
    slots: Vec<Result<DeleteCall, Outcome>>,
}

impl DeletePlan {
    /// `current` holds what `items` allow right now, in the same order.
    pub fn new(
        items: &[ItemRef],
        current: Vec<Result<DeleteRights, AdapterError>>,
        current_user_id: i64,
    ) -> Self {
        let mut calls: HashMap<DeleteCall, Vec<i64>> = HashMap::new();
        let slots = items
            .iter()
            .zip(current)
            .map(|(item, rights)| {
                let rights = rights.map_err(|error| outcome_for(&Err(error)))?;
                let (chat_id, message_id) = parse_message_ref(item).ok_or_else(|| Outcome::Failed {
                    reason: "unparseable Telegram message ref".into(),
                    retryable: false,
                })?;
                if rights.reach(chat_id, current_user_id) != previewed_reach(item) {
                    return Err(Outcome::Failed {
                        reason: "Telegram changed how far this message can be deleted, so it stayed".into(),
                        retryable: false,
                    });
                }
                let call = DeleteCall { chat_id, revoke: rights.for_everyone };
                calls.entry(call).or_default().push(message_id);
                Ok(call)
            })
            .collect();
        Self { calls, slots }
    }

    /// One outcome per item, in input order, from the result of each call.
    pub fn outcomes(&self, results: &HashMap<DeleteCall, Result<(), AdapterError>>) -> Vec<Outcome> {
        self.slots
            .iter()
            .map(|slot| match slot {
                Err(outcome) => outcome.clone(),
                Ok(call) => match results.get(call) {
                    Some(result) => outcome_for(result),
                    None => Outcome::Failed {
                        reason: format!("no delete result for chat {}", call.chat_id),
                        retryable: false,
                    },
                },
            })
            .collect()
    }
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

    const ME: i64 = 42;
    const FOR_EVERYONE: DeleteRights = DeleteRights { for_everyone: true, for_self: true };
    const ONLY_FOR_SELF: DeleteRights = DeleteRights { for_everyone: false, for_self: true };
    const NEITHER: DeleteRights = DeleteRights { for_everyone: false, for_self: false };

    fn message(chat_id: i64, message_id: i64, reach: DeleteReach) -> ItemRef {
        iref(
            &format!("telegram:{chat_id}:{message_id}"),
            Some(&message_token(chat_id, message_id, reach)),
        )
    }

    fn all_succeed(plan: &DeletePlan) -> HashMap<DeleteCall, Result<(), AdapterError>> {
        plan.calls.keys().map(|call| (*call, Ok(()))).collect()
    }

    #[test]
    fn telegrams_flags_decide_how_far_a_delete_goes() {
        assert_eq!(FOR_EVERYONE.reach(7, ME), DeleteReach::Everyone);
        assert_eq!(ONLY_FOR_SELF.reach(7, ME), DeleteReach::OnlyForSelf);
        assert_eq!(NEITHER.reach(7, ME), DeleteReach::Nowhere);
        let supergroup = DeleteRights { for_everyone: true, for_self: false };
        assert_eq!(supergroup.reach(-100, ME), DeleteReach::Everyone);
    }

    #[test]
    fn saved_messages_are_gone_for_everyone_who_could_see_them() {
        assert_eq!(ONLY_FOR_SELF.reach(ME, ME), DeleteReach::Everyone);
    }

    #[test]
    fn a_saved_message_goes_without_revoke_though_it_reads_as_everyone() {
        let items = [message(ME, 1, DeleteReach::Everyone)];

        let plan = DeletePlan::new(&items, vec![Ok(ONLY_FOR_SELF)], ME);

        assert_eq!(plan.calls[&DeleteCall { chat_id: ME, revoke: false }], [1]);
    }

    #[test]
    fn a_token_still_parses_when_it_holds_the_reach() {
        assert_eq!(
            parse_message_ref(&message(-1001234, 9, DeleteReach::OnlyForSelf)),
            Some((-1001234, 9))
        );
    }

    #[test]
    fn a_mixed_batch_splits_into_one_call_per_mode() {
        let items = [
            message(7, 1, DeleteReach::Everyone),
            message(7, 2, DeleteReach::OnlyForSelf),
            message(7, 3, DeleteReach::Everyone),
        ];

        let plan = DeletePlan::new(&items, vec![Ok(FOR_EVERYONE), Ok(ONLY_FOR_SELF), Ok(FOR_EVERYONE)], ME);

        assert_eq!(plan.calls[&DeleteCall { chat_id: 7, revoke: true }], [1, 3]);
        assert_eq!(plan.calls[&DeleteCall { chat_id: 7, revoke: false }], [2]);
        let outcomes = plan.outcomes(&all_succeed(&plan));
        assert!(outcomes.iter().all(|outcome| matches!(outcome, Outcome::Deleted)));
    }

    #[test]
    fn a_message_that_can_no_longer_go_for_everyone_stays_and_the_rest_still_go() {
        let items = [message(7, 1, DeleteReach::Everyone), message(7, 2, DeleteReach::Everyone)];

        let plan = DeletePlan::new(&items, vec![Ok(ONLY_FOR_SELF), Ok(FOR_EVERYONE)], ME);

        assert_eq!(plan.calls.len(), 1);
        assert_eq!(plan.calls[&DeleteCall { chat_id: 7, revoke: true }], [2]);
        let outcomes = plan.outcomes(&all_succeed(&plan));
        assert!(matches!(outcomes[0], Outcome::Failed { retryable: false, .. }));
        assert!(matches!(outcomes[1], Outcome::Deleted));
    }

    #[test]
    fn a_message_telegram_will_not_delete_does_not_sink_its_batch() {
        let items = [message(7, 1, DeleteReach::Everyone), message(7, 2, DeleteReach::Everyone)];

        let plan = DeletePlan::new(&items, vec![Ok(NEITHER), Ok(FOR_EVERYONE)], ME);

        let outcomes = plan.outcomes(&all_succeed(&plan));
        assert!(matches!(outcomes[0], Outcome::Failed { .. }));
        assert!(matches!(outcomes[1], Outcome::Deleted));
    }

    #[test]
    fn a_failed_call_only_touches_its_own_mode_and_chat_and_order_is_kept() {
        let items = [
            message(1, 10, DeleteReach::Everyone),
            message(2, 20, DeleteReach::Everyone),
            iref("nope", None),
            message(1, 11, DeleteReach::OnlyForSelf),
        ];
        let current = vec![
            Ok(FOR_EVERYONE),
            Ok(FOR_EVERYONE),
            Err(AdapterError::Platform("unreadable".into())),
            Ok(ONLY_FOR_SELF),
        ];

        let plan = DeletePlan::new(&items, current, ME);
        let mut results = all_succeed(&plan);
        results.insert(
            DeleteCall { chat_id: 2, revoke: true },
            Err(AdapterError::RateLimited { retry_after_secs: 7 }),
        );

        let outcomes = plan.outcomes(&results);
        assert_eq!(outcomes.len(), 4);
        assert!(matches!(outcomes[0], Outcome::Deleted));
        assert!(matches!(outcomes[1], Outcome::RateLimited { retry_after_secs: 7 }));
        assert!(matches!(outcomes[2], Outcome::Failed { retryable: false, .. }));
        assert!(matches!(outcomes[3], Outcome::Deleted));
    }

    #[test]
    fn a_message_already_gone_when_checked_counts_as_skipped() {
        let items = [message(5, 1, DeleteReach::Everyone)];

        let plan = DeletePlan::new(&items, vec![Err(AdapterError::NotFound)], ME);

        assert!(plan.calls.is_empty());
        assert!(matches!(plan.outcomes(&HashMap::new())[0], Outcome::Skipped { .. }));
    }

    #[test]
    fn a_call_that_finds_the_messages_gone_counts_them_as_skipped() {
        let items = [message(5, 1, DeleteReach::Everyone)];
        let plan = DeletePlan::new(&items, vec![Ok(FOR_EVERYONE)], ME);
        let results = HashMap::from([(DeleteCall { chat_id: 5, revoke: true }, Err(AdapterError::NotFound))]);

        assert!(matches!(plan.outcomes(&results)[0], Outcome::Skipped { .. }));
    }
}

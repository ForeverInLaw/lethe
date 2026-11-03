//! What a run leaves the store to tell per scope, such as a Telegram chat.

use std::sync::Arc;

use lethe_adapter::{AdapterError, Item};
use lethe_store::ScopeOutcome;

use super::tests::{downloaded, media_item, run_media, MediaAdapter};
use crate::RunControl;

fn in_chat(id: &str, chat: &str, files: &[(&str, u64)]) -> Item {
    Item { scope_id: Some(chat.into()), ..media_item(id, files) }
}

#[tokio::test]
async fn a_run_records_what_it_deleted_and_failed_in_each_chat() {
    let adapter = Arc::new(MediaAdapter::new(
        vec![
            in_chat("a1", "a", &[]),
            in_chat("a2", "a", &[("gone", 3)]),
            in_chat("b1", "b", &[]),
        ],
        |media, _| match media.url.as_str() {
            "gone" => Err(AdapterError::FileRefused("the file is gone".into())),
            _ => Ok(downloaded(b"")),
        },
    ));

    let run = run_media(adapter, RunControl::new()).await;

    assert_eq!(
        run.store.scope_outcomes("media").unwrap(),
        vec![
            ScopeOutcome { scope_id: "a".into(), deleted: 1, failed: 1 },
            ScopeOutcome { scope_id: "b".into(), deleted: 1, failed: 0 },
        ]
    );
}

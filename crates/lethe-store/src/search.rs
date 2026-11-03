//! Finding preview rows by their text and file names. SQLite folds case only for
//! ASCII, so the comparison runs through a Rust function that folds Cyrillic as well.

use rusqlite::functions::FunctionFlags;
use rusqlite::Connection;
use unicode_normalization::UnicodeNormalization;

use crate::file_facts;

/// The SQL function that folds a row's text for `contains`.
const FOLD: &str = "lethe_fold";

/// Lets this connection's statements call `lethe_fold`.
pub(crate) fn register(conn: &Connection) -> rusqlite::Result<()> {
    conn.create_scalar_function(
        FOLD,
        1,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        |ctx| Ok(ctx.get::<Option<String>>(0)?.map(|text| fold(&text))),
    )
}

/// Rows whose text or file name holds parameter `?{search}`, which `needle` gives,
/// or whose subtype is in the JSON array `?{subtypes}`. Matches every row when the
/// search is blank.
pub(crate) fn matches(search: usize, subtypes: usize) -> String {
    format!(
        "(?{search} = '' OR instr({FOLD}(text), ?{search}) > 0
          OR instr({FOLD}({}), ?{search}) > 0
          OR subtype IN (SELECT value FROM json_each(?{subtypes})))",
        file_facts::FILE_NAME
    )
}

/// The search text as `matches` compares it.
pub(crate) fn needle(search: &str) -> String {
    fold(search.trim())
}

/// Unicode case folding of the composed text, with ё read as е. Lowercasing alone
/// would keep σ and a word-final ς apart.
fn fold(text: &str) -> String {
    caseless::default_case_fold_str(&fold_yo_ye(text))
}

/// NFC-normalize and fold ё/Ё → е/Е so Cyrillic searches match as users expect.
/// The keyword filter uses it too.
pub fn fold_yo_ye(text: &str) -> String {
    text.nfc()
        .map(|c| match c {
            'ё' => 'е',
            'Ё' => 'Е',
            other => other,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use lethe_adapter::MediaRef;

    use crate::tests::{run_with, snap};
    use crate::{ItemFilter, ItemGroup, ItemQuery, ItemSnapshot, ItemState, Store};

    fn texted(id: &str, text: &str) -> ItemSnapshot {
        ItemSnapshot {
            text: Some(text.into()),
            ..snap(id, ItemState::Pending)
        }
    }

    fn found(store: &Store, search: &str) -> Vec<String> {
        let query = ItemQuery { filter: ItemFilter { search, ..Default::default() }, limit: 10, ..Default::default() };
        let rows = store.preview_items("r", &query).unwrap();
        rows.into_iter().map(|row| row.platform_id).collect()
    }

    #[test]
    fn preview_items_find_text_whatever_its_case() {
        let s = run_with(&[
            texted("cat", "Котлета на ужин"),
            texted("dog", "Собака"),
            snap("silent", ItemState::Pending),
            // Lowercasing turns a word-final Σ into ς; folding reads every sigma as σ.
            texted("road", "ΟΔΟΣ"),
        ]);

        assert_eq!(found(&s, "кОТ"), ["cat"]);
        assert_eq!(found(&s, "οδοσ"), ["road"]);
    }

    #[test]
    fn preview_items_find_yo_and_ye_as_one_letter() {
        let s = run_with(&[
            texted("tree", "Ёлка во дворе"),
            texted("spruce", "еловая ветка"),
            // ё as е followed by a combining diaeresis.
            texted("decomposed", "ну \u{0435}\u{0308}жик"),
        ]);

        assert_eq!(found(&s, "ел"), ["spruce", "tree"]);
        assert_eq!(found(&s, "ЁЛ"), ["spruce", "tree"]);
        assert_eq!(found(&s, "ёж"), ["decomposed"]);
    }

    #[test]
    fn preview_items_find_rows_by_their_file_name() {
        let s = run_with(&[ItemSnapshot {
            text: None,
            media: vec![MediaRef { url: "u".into(), mime: None, file_name: Some("Отчёт.pdf".into()), size: None }],
            ..snap("document", ItemState::Pending)
        }]);

        assert_eq!(found(&s, "отчет"), ["document"]);
    }

    #[test]
    fn preview_items_find_rows_by_the_subtypes_the_search_names() {
        let typed = |id: &str, subtype, text: Option<&str>| ItemSnapshot {
            subtype: Some(subtype),
            text: text.map(Into::into),
            ..snap(id, ItemState::Pending)
        };
        let s = run_with(&[
            typed("joined", "chat_join", None),
            typed("pinned", "pin_message", None),
            typed("poll", "poll", Some("tea or coffee")),
        ]);
        let found = |search, subtypes: &[&str]| {
            let filter = ItemFilter { search, matching_subtypes: subtypes, ..Default::default() };
            let query = ItemQuery { filter, limit: 10, ..Default::default() };
            let rows = s.preview_items("r", &query).unwrap();
            rows.into_iter().map(|row| (row.platform_id, row.subtype)).collect::<Vec<_>>()
        };

        // The app words the subtypes, so it says which ones the search names.
        assert_eq!(found("joined", &["chat_join"]), [("joined".to_owned(), Some("chat_join".to_owned()))]);
        assert_eq!(found("coffee", &[]), [("poll".to_owned(), Some("poll".to_owned()))]);
        // A blank search lists every row, whatever subtypes come with it.
        assert_eq!(found("", &["chat_join"]).len(), 3);
    }

    #[test]
    fn preview_items_page_through_matches_within_a_group() {
        let dated = |id: &str, text: &str, at, state| ItemSnapshot {
            created_at_secs: Some(at),
            state,
            ..texted(id, text)
        };
        let s = run_with(&[
            dated("kept-old", "отпуск в Сочи", 1, ItemState::Protected),
            dated("other", "работа", 2, ItemState::Protected),
            dated("kept-new", "Отпуск снова", 3, ItemState::Protected),
            dated("going", "отпуск", 4, ItemState::Pending),
        ]);
        let page = |offset| {
            let query = ItemQuery {
                filter: ItemFilter { group: ItemGroup::Protected, search: " отпуск ", ..Default::default() },
                offset,
                limit: 1,
            };
            let rows = s.preview_items("r", &query).unwrap();
            rows.into_iter().map(|row| row.platform_id).collect::<Vec<_>>()
        };

        assert_eq!(page(0), ["kept-new"]);
        assert_eq!(page(1), ["kept-old"]);
        assert!(page(2).is_empty());
    }
}

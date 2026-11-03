//! Finding preview rows by their text. SQLite folds case only for ASCII, so the
//! comparison runs through a Rust function that folds Cyrillic as well.

use rusqlite::functions::FunctionFlags;
use rusqlite::Connection;
use unicode_normalization::UnicodeNormalization;

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

/// Rows whose text holds parameter `?{param}`, which `needle` gives. Matches every
/// row when that parameter is blank.
pub(crate) fn contains(param: usize) -> String {
    format!("(?{param} = '' OR instr({FOLD}(text), ?{param}) > 0)")
}

/// The search text as `contains` compares it.
pub(crate) fn needle(search: &str) -> String {
    fold(search.trim())
}

/// Lower case, composed, with ё read as е.
fn fold(text: &str) -> String {
    fold_yo_ye(text).to_lowercase()
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
    use crate::tests::{run_with, snap};
    use crate::{ItemGroup, ItemQuery, ItemSnapshot, ItemState, Store};

    fn texted(id: &str, text: &str) -> ItemSnapshot {
        ItemSnapshot {
            text: Some(text.into()),
            ..snap(id, ItemState::Pending)
        }
    }

    fn found(store: &Store, search: &str) -> Vec<String> {
        let query = ItemQuery { search, limit: 10, ..Default::default() };
        let rows = store.preview_items("r", &query).unwrap();
        rows.into_iter().map(|row| row.platform_id).collect()
    }

    #[test]
    fn preview_items_find_text_whatever_its_case() {
        let s = run_with(&[
            texted("cat", "Котлета на ужин"),
            texted("dog", "Собака"),
            snap("silent", ItemState::Pending),
        ]);

        assert_eq!(found(&s, "кОТ"), ["cat"]);
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
                group: ItemGroup::Protected,
                search: " отпуск ",
                offset,
                limit: 1,
                ..Default::default()
            };
            let rows = s.preview_items("r", &query).unwrap();
            rows.into_iter().map(|row| row.platform_id).collect::<Vec<_>>()
        };

        assert_eq!(page(0), ["kept-new"]);
        assert_eq!(page(1), ["kept-old"]);
        assert!(page(2).is_empty());
    }
}

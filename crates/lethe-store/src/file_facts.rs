//! What a preview row says about its files, read from the stored `media_json`, so
//! a person can tell a photo from a PDF before choosing what stays.

/// The name of the row's first file that has one.
pub(crate) const FILE_NAME: &str = "(SELECT json_extract(value, '$.file_name') FROM json_each(media_json)
   WHERE json_extract(value, '$.file_name') IS NOT NULL LIMIT 1)";

/// The bytes of the row's files; NULL unless every file's size is known, so a
/// partial sum never passes for the whole. A size of 0 is one TDLib does not know.
pub(crate) const FILE_SIZE: &str = "(SELECT CASE WHEN COUNT(*) = COUNT(NULLIF(json_extract(value, '$.size'), 0))
   THEN SUM(json_extract(value, '$.size')) END FROM json_each(media_json))";

#[cfg(test)]
mod tests {
    use lethe_adapter::MediaRef;

    use crate::tests::{run_with, snap};
    use crate::{ItemQuery, ItemSnapshot, ItemState};

    #[test]
    fn preview_items_name_the_first_named_file_and_add_up_sizes_only_when_all_are_known() {
        let file = |name: Option<&str>, size| MediaRef {
            url: "u".into(),
            mime: None,
            file_name: name.map(Into::into),
            size,
        };
        let with_media = |id: &str, at, media| ItemSnapshot {
            created_at_secs: Some(at),
            media,
            ..snap(id, ItemState::Pending)
        };
        let s = run_with(&[
            with_media("document", 4, vec![file(Some("report.pdf"), Some(2048))]),
            with_media("album", 3, vec![file(None, Some(3)), file(Some("b.jpg"), Some(4))]),
            // TDLib gives 0 for a size it does not know.
            with_media("unsized", 2, vec![file(None, Some(0))]),
            with_media("partly sized", 2, vec![file(None, Some(5)), file(None, None)]),
            with_media("text", 1, Vec::new()),
        ]);

        let rows = s.preview_items("r", &ItemQuery { limit: 10, ..Default::default() }).unwrap();

        let facts: Vec<_> = rows.iter().map(|row| (row.file_name.as_deref(), row.file_size)).collect();
        assert_eq!(
            facts,
            [
                (Some("report.pdf"), Some(2048)),
                (Some("b.jpg"), Some(7)),
                (None, None),
                (None, None),
                (None, None),
            ]
        );
    }
}

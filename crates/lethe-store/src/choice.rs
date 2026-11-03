//! The person's choice over many preview rows at once: what goes and what stays.

use rusqlite::params;

use crate::{ItemFilter, ItemState, Result, Store};

/// How the rows of a filter stand: going with the run, or kept by the person.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct ChoiceCounts {
    pub going: u64,
    pub kept: u64,
}

/// The states a row moves between when it is kept (`protected`) or let go again.
pub(crate) fn protection_move(protected: bool) -> (ItemState, ItemState) {
    if protected {
        (ItemState::Pending, ItemState::Protected)
    } else {
        (ItemState::Protected, ItemState::Pending)
    }
}

impl Store {
    /// Keeps, or lets go again, every row the filter covers, loaded on screen or
    /// not, in one statement. Returns how many rows changed. Like
    /// `set_item_protected`, it leaves rows that already ran, and changes nothing
    /// once the run executes.
    pub fn set_items_protected(&self, run_id: &str, filter: &ItemFilter, protected: bool) -> Result<u64> {
        let (from, to) = protection_move(protected);
        let (run_id, content_type, needle, subtypes) = filter.params(run_id)?;
        let changed = self.conn.execute(
            &format!(
                "UPDATE items SET state = ?6
                 WHERE {} AND state = ?5
                   AND NOT EXISTS (SELECT 1 FROM runs WHERE run_id = ?1 AND state = 'executing')",
                filter.condition()
            ),
            params![run_id, content_type, needle, subtypes, from.as_str(), to.as_str()],
        )?;
        Ok(changed as u64)
    }

    /// How the rows the filter covers stand, for a header checkbox over all of them.
    pub fn choice_counts(&self, run_id: &str, filter: &ItemFilter) -> Result<ChoiceCounts> {
        let (run_id, content_type, needle, subtypes) = filter.params(run_id)?;
        let (going, kept) = self.conn.query_row(
            &format!(
                "SELECT COUNT(*) FILTER (WHERE state = 'pending'), COUNT(*) FILTER (WHERE state = 'protected')
                 FROM items WHERE {}",
                filter.condition()
            ),
            params![run_id, content_type, needle, subtypes],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
        )?;
        Ok(ChoiceCounts { going: going as u64, kept: kept as u64 })
    }
}

#[cfg(test)]
mod tests {
    use lethe_adapter::{ContentType, Outcome};

    use crate::tests::{run_with, snap};
    use crate::{ChoiceCounts, ItemFilter, ItemGroup, ItemSnapshot, ItemState, RunState};

    fn row(id: &str, content_type: ContentType, text: &str, state: ItemState) -> ItemSnapshot {
        ItemSnapshot {
            content_type,
            text: Some(text.into()),
            ..snap(id, state)
        }
    }

    #[test]
    fn a_bulk_choice_covers_every_row_of_the_filter_and_no_other() {
        let s = run_with(&[
            row("trip", ContentType::Post, "Отпуск", ItemState::Pending),
            row("trip-kept", ContentType::Post, "отпуск снова", ItemState::Protected),
            row("trip-like", ContentType::Reaction, "отпуск", ItemState::Pending),
            row("work", ContentType::Post, "работа", ItemState::Pending),
        ]);
        let trip_posts = ItemFilter {
            content_type: Some(ContentType::Post),
            search: "отпуск",
            ..Default::default()
        };

        assert_eq!(s.choice_counts("r", &trip_posts).unwrap(), ChoiceCounts { going: 1, kept: 1 });
        assert_eq!(s.set_items_protected("r", &trip_posts, true).unwrap(), 1);
        assert_eq!(s.choice_counts("r", &trip_posts).unwrap(), ChoiceCounts { going: 0, kept: 2 });
        let everything = s.choice_counts("r", &ItemFilter::default()).unwrap();
        assert_eq!(everything, ChoiceCounts { going: 2, kept: 2 });

        assert_eq!(s.set_items_protected("r", &trip_posts, false).unwrap(), 2);
        let everything = s.choice_counts("r", &ItemFilter::default()).unwrap();
        assert_eq!(everything, ChoiceCounts { going: 4, kept: 0 });
    }

    #[test]
    fn a_bulk_choice_leaves_rows_that_ran_or_cannot_go() {
        let mut s = run_with(&[
            snap("gone", ItemState::Pending),
            snap("stuck", ItemState::Undeletable),
            snap("left", ItemState::Pending),
        ]);
        s.record_outcomes("r", &[("gone".into(), Outcome::Deleted)]).unwrap();
        let undeletable = ItemFilter { group: ItemGroup::Undeletable, ..Default::default() };

        assert_eq!(s.set_items_protected("r", &undeletable, true).unwrap(), 0);
        assert_eq!(s.set_items_protected("r", &ItemFilter::default(), true).unwrap(), 1);
        let counts = s.preview_counts("r").unwrap();
        assert_eq!((counts.deleted, counts.undeletable, counts.protected), (1, 1, 1));
    }

    #[test]
    fn a_bulk_choice_is_refused_once_the_run_executes() {
        let s = run_with(&[snap("1", ItemState::Pending), snap("2", ItemState::Protected)]);
        s.set_run_state("r", RunState::Executing).unwrap();

        assert_eq!(s.set_items_protected("r", &ItemFilter::default(), true).unwrap(), 0);
        assert_eq!(s.set_items_protected("r", &ItemFilter::default(), false).unwrap(), 0);
        let counts = s.preview_counts("r").unwrap();
        assert_eq!((counts.pending, counts.protected), (1, 1));
    }
}

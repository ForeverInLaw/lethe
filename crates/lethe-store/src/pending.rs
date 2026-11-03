//! Rows waiting to run: what their files need on disk, and which of them go only
//! if the person agrees, because the backup cannot hold them in full or the delete
//! hides them only from this account.

use rusqlite::params;

use crate::{ItemState, Result, Store};

/// A row the backup cannot hold in full.
const BACKUP_GAP: &str = "items.backup_gap IS NOT NULL";
/// A row whose delete hides it only from this account.
pub(crate) const ONLY_FOR_SELF: &str = "items.delete_reach = 'only_for_self'";

/// Files still to be archived for a run, as far as Phase 1 knows their sizes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PendingMedia {
    pub bytes: u64,
    pub largest_bytes: u64,
}

/// Rows waiting to run that go only if the person agrees, and how many need both
/// agreements, so a screen can tell what stays under any choice.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PendingConsents {
    pub backup_gaps: u64,
    pub only_for_self: u64,
    pub both: u64,
}

/// Which rows that go only with the person's agreement they agreed to delete.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Consents {
    pub backup_gaps: bool,
    pub only_for_self: bool,
}

/// The waiting rows of run `?1` that go with the agreements `?2` (backup gaps)
/// and `?3` (only for self).
pub(crate) fn goes_with_consents() -> String {
    format!(
        "items.run_id = ?1 AND items.state = 'pending'
         AND (?2 OR NOT ({BACKUP_GAP})) AND (?3 OR NOT ({ONLY_FOR_SELF}))"
    )
}

impl Consents {
    /// The parameters `goes_with_consents` takes.
    pub(crate) fn params(self, run_id: &str) -> (&str, bool, bool) {
        (run_id, self.backup_gaps, self.only_for_self)
    }
}

impl Store {
    /// Files of the waiting rows that go with the agreements given.
    pub fn pending_media(&self, run_id: &str, consents: Consents) -> Result<PendingMedia> {
        let mut stmt = self.conn.prepare_cached(&format!(
            "SELECT COALESCE(SUM(json_extract(file.value, '$.size')), 0),
                    COALESCE(MAX(json_extract(file.value, '$.size')), 0)
             FROM items, json_each(items.media_json) AS file
             WHERE {}",
            goes_with_consents()
        ))?;
        let params = consents.params(run_id);
        Ok(stmt.query_row(params, |r| {
            Ok(PendingMedia {
                bytes: r.get::<_, i64>(0)? as u64,
                largest_bytes: r.get::<_, i64>(1)? as u64,
            })
        })?)
    }

    pub fn pending_consents(&self, run_id: &str) -> Result<PendingConsents> {
        let mut stmt = self.conn.prepare_cached(&format!(
            "SELECT COALESCE(SUM({BACKUP_GAP}), 0),
                    COALESCE(SUM({ONLY_FOR_SELF}), 0),
                    COALESCE(SUM({BACKUP_GAP} AND {ONLY_FOR_SELF}), 0)
             FROM items WHERE items.run_id = ?1 AND items.state = 'pending'"
        ))?;
        Ok(stmt.query_row(params![run_id], |r| {
            Ok(PendingConsents {
                backup_gaps: r.get::<_, i64>(0)? as u64,
                only_for_self: r.get::<_, i64>(1)? as u64,
                both: r.get::<_, i64>(2)? as u64,
            })
        })?)
    }

    /// Keeps the rows the backup cannot hold in full, for a person who did not agree
    /// to losing part of them.
    pub fn protect_backup_gaps(&self, run_id: &str) -> Result<()> {
        self.protect_pending(run_id, BACKUP_GAP)
    }

    /// Keeps the rows only this account would stop seeing, for a person who did not
    /// agree to leave them with everyone else.
    pub fn protect_only_for_self(&self, run_id: &str) -> Result<()> {
        self.protect_pending(run_id, ONLY_FOR_SELF)
    }

    fn protect_pending(&self, run_id: &str, which: &str) -> Result<()> {
        self.conn.execute(
            &format!(
                "UPDATE items SET state = ?1
                 WHERE items.run_id = ?2 AND items.state = 'pending' AND {which}"
            ),
            params![ItemState::Protected.as_str(), run_id],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::{run_with, snap};
    use crate::{Consents, ItemSnapshot, ItemState, PendingMedia};
    use lethe_adapter::{DeleteReach, MediaRef};

    fn sized(id: &str, state: ItemState, sizes: &[Option<u64>]) -> ItemSnapshot {
        ItemSnapshot {
            media: sizes
                .iter()
                .map(|size| MediaRef {
                    url: format!("file-{id}"),
                    mime: None,
                    file_name: None,
                    size: *size,
                })
                .collect(),
            ..snap(id, state)
        }
    }

    #[test]
    fn pending_media_sizes_only_files_that_will_be_archived() {
        let s = run_with(&[
            sized("a", ItemState::Pending, &[Some(100), Some(700)]),
            sized("b", ItemState::Pending, &[None]),
            sized("c", ItemState::Protected, &[Some(9_000)]),
            sized("d", ItemState::Pending, &[]),
        ]);

        let media = s.pending_media("r", Consents::default()).unwrap();

        assert_eq!(media.bytes, 800);
        assert_eq!(media.largest_bytes, 700);
    }

    #[test]
    fn pending_media_sizes_what_needs_agreement_only_once_agreed() {
        let waiting = |id: &str, size: u64| sized(id, ItemState::Pending, &[Some(size)]);
        let s = run_with(&[
            waiting("plain", 1),
            ItemSnapshot {
                backup_gap: Some("too big".into()),
                ..waiting("gap", 10)
            },
            ItemSnapshot {
                delete_reach: DeleteReach::OnlyForSelf,
                ..waiting("self", 100)
            },
            ItemSnapshot {
                backup_gap: Some("too big".into()),
                delete_reach: DeleteReach::OnlyForSelf,
                ..waiting("both", 1_000)
            },
        ]);
        let bytes = |backup_gaps, only_for_self| {
            s.pending_media(
                "r",
                Consents {
                    backup_gaps,
                    only_for_self,
                },
            )
            .unwrap()
            .bytes
        };

        assert_eq!(bytes(false, false), 1);
        assert_eq!(bytes(true, false), 11);
        assert_eq!(bytes(false, true), 101);
        assert_eq!(bytes(true, true), 1_111);
    }

    #[test]
    fn pending_media_is_empty_for_a_run_without_files() {
        let s = run_with(&[]);
        assert_eq!(
            s.pending_media("r", Consents::default()).unwrap(),
            PendingMedia::default()
        );
    }
}
